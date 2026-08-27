use std::collections::HashMap;

use color_eyre::eyre::{Result, eyre};
use serde_saphyr::granit_parser::{Event, Parser, Span};

struct Node {
    span: Span,
    value: Value,
}

enum Value {
    Scalar(String),
    Sequence(Vec<Node>),
    Mapping(Vec<Node>),
    Alias(usize),
}

struct Comment {
    span: Span,
    text: String,
}

pub(super) fn normalize(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        "#".to_owned()
    } else {
        format!("# {text}")
    }
}

/// Keep presentation metadata separate from the typed manifests, which discard comments.
/// Matching sequence items by value lets comments follow installers and sorted sets.
pub(super) fn preserve(input: &str, output: &str, header_lines: usize) -> Result<String> {
    if !input
        .lines()
        .skip(header_lines)
        .any(|line| line.contains('#'))
    {
        return Ok(output.to_owned());
    }

    let (source, comments) = parse(input)?;
    if comments
        .iter()
        .all(|comment| comment.span.start.line() <= header_lines)
    {
        return Ok(output.to_owned());
    }
    let (target, _) = parse(output)?;
    let mut locations = HashMap::new();
    match_nodes(&source, &target, &mut locations);

    let mut anchors = Vec::new();
    source.anchors(&mut anchors);
    anchors.sort_by_key(|span| span.start.byte_offset());
    let lines = output.lines().collect::<Vec<_>>();
    let mut above = vec![Vec::new(); lines.len()];
    let mut inline = vec![Vec::new(); lines.len()];
    let mut trailing = Vec::new();

    for comment in comments {
        if comment.span.start.line() <= header_lines {
            continue;
        }
        let offset = comment.span.start.byte_offset().unwrap();
        let line_start = input[..offset].rfind('\n').map_or(0, |index| index + 1);
        let is_inline = !input[line_start..offset].trim().is_empty();
        let anchor = if is_inline {
            anchors.iter().rev().find(|span| {
                span.start.byte_offset().unwrap() < offset
                    && span.start.line() == comment.span.start.line()
            })
        } else {
            anchors
                .iter()
                .find(|span| span.start.byte_offset().unwrap() > offset)
        };
        let Some(target) = anchor.and_then(|span| locations.get(&span.start.byte_offset())) else {
            // Comments on omitted fields and at EOF still belong to the document.
            trailing.push(comment.text);
            continue;
        };
        let line = target.start.line() - 1;
        if is_inline {
            inline[line].push(comment.text);
        } else {
            above[line].push(comment.text);
        }
    }

    let mut result = String::new();
    for (index, line) in lines.iter().enumerate() {
        let indent = line.len() - line.trim_start().len();
        for comment in &above[index] {
            result.push_str(&line[..indent]);
            result.push_str(comment);
            result.push('\n');
        }
        result.push_str(line);
        for comment in &inline[index] {
            result.push(' ');
            result.push_str(comment);
        }
        result.push('\n');
    }
    for comment in trailing {
        result.push_str(&comment);
        result.push('\n');
    }
    Ok(result)
}

fn parse(input: &str) -> Result<(Node, Vec<Comment>)> {
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut comments = Vec::new();
    for event in Parser::new_from_str(input) {
        let (event, span) = event?;
        let value = match event {
            Event::Comment(text, _) => {
                comments.push(Comment {
                    span,
                    text: normalize(&text),
                });
                continue;
            }
            Event::MappingStart(..) => {
                stack.push(Node {
                    span,
                    value: Value::Mapping(Vec::new()),
                });
                continue;
            }
            Event::SequenceStart(..) => {
                stack.push(Node {
                    span,
                    value: Value::Sequence(Vec::new()),
                });
                continue;
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let mut node = stack
                    .pop()
                    .ok_or_else(|| eyre!("Missing YAML collection"))?;
                node.span.end = span.end;
                node
            }
            Event::Scalar(value, ..) => Node {
                span,
                value: Value::Scalar(value.into_owned()),
            },
            Event::Alias(anchor) => Node {
                span,
                value: Value::Alias(anchor),
            },
            _ => continue,
        };
        if let Some(parent) = stack.last_mut() {
            match &mut parent.value {
                Value::Mapping(nodes) | Value::Sequence(nodes) => nodes.push(value),
                _ => unreachable!(),
            }
        } else {
            root = Some(value);
        }
    }
    Ok((
        root.ok_or_else(|| eyre!("Missing YAML document"))?,
        comments,
    ))
}

impl Node {
    fn anchors<'a>(&'a self, anchors: &mut Vec<&'a Span>) {
        match &self.value {
            Value::Mapping(nodes) | Value::Sequence(nodes) => {
                for node in nodes {
                    node.anchors(anchors);
                }
            }
            Value::Scalar(_) | Value::Alias(_) => anchors.push(&self.span),
        }
    }

    fn equivalent(&self, other: &Self, key: &str) -> bool {
        match (&self.value, &other.value) {
            (Value::Scalar(left), Value::Scalar(right)) => {
                if key.ends_with("Sha256") {
                    left.eq_ignore_ascii_case(right)
                } else if matches!(key, "RelativeFilePath" | "DefaultInstallLocation") {
                    left.replace('/', "\\") == right.replace('/', "\\")
                } else {
                    left == right
                }
            }
            (Value::Mapping(left), Value::Mapping(right)) => {
                left.len() == right.len()
                    && right.as_chunks::<2>().0.iter().all(|pair| {
                        left.as_chunks::<2>().0.iter().any(|candidate| {
                            candidate[0].equivalent(&pair[0], "")
                                && candidate[1].equivalent(&pair[1], pair[0].key())
                        })
                    })
            }
            (Value::Sequence(left), Value::Sequence(right)) => {
                let mut used = vec![false; left.len()];
                left.len() == right.len()
                    && right.iter().all(|item| {
                        if let Some(index) =
                            left.iter().enumerate().position(|(index, candidate)| {
                                !used[index] && candidate.equivalent(item, key)
                            })
                        {
                            used[index] = true;
                            true
                        } else {
                            false
                        }
                    })
            }
            (Value::Alias(left), Value::Alias(right)) => left == right,
            _ => false,
        }
    }

    fn key(&self) -> &str {
        match &self.value {
            Value::Scalar(value) => value,
            _ => "",
        }
    }
}

fn match_nodes<'a>(
    source: &Node,
    target: &'a Node,
    locations: &mut HashMap<Option<usize>, &'a Span>,
) {
    locations.insert(source.span.start.byte_offset(), &target.span);
    match (&source.value, &target.value) {
        (Value::Mapping(source), Value::Mapping(target)) => {
            for pair in source.as_chunks::<2>().0 {
                if let Some(other) = target
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .find(|other| pair[0].equivalent(&other[0], ""))
                {
                    match_nodes(&pair[0], &other[0], locations);
                    match_nodes(&pair[1], &other[1], locations);
                }
            }
        }
        (Value::Sequence(source), Value::Sequence(target)) => {
            let mut used = vec![false; target.len()];
            for node in source {
                if let Some((index, other)) = target
                    .iter()
                    .enumerate()
                    .find(|(index, other)| !used[*index] && node.equivalent(other, ""))
                {
                    used[index] = true;
                    match_nodes(node, other, locations);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::preserve;

    #[test]
    fn preserves_comments_without_changing_multiline_or_quoted_values() {
        let input = "Description: | # description\n  text # part of the value\n  # also part of the value\nName: 'value # with a hash' # name\n";
        let canonical = "Name: 'value # with a hash'\nDescription: |\n  text # part of the value\n  # also part of the value\n";

        let formatted = preserve(input, canonical, 0).unwrap();

        assert!(formatted.contains("Description: | # description\n"));
        assert!(formatted.contains("Name: 'value # with a hash' # name\n"));
        assert_eq!(
            serde_saphyr::from_str::<serde_json::Value>(input).unwrap(),
            serde_saphyr::from_str::<serde_json::Value>(&formatted).unwrap(),
        );
        assert_eq!(preserve(&formatted, canonical, 0).unwrap(), formatted);
    }

    #[test]
    fn normalizes_comments_without_trimming_scalar_contents() {
        let input = "Description: | #description \t\n  text #nospace  \n  #literal  \nName: 'value #nospace  ' #\tname \t\n#final note \t\n# \t\n";
        let canonical =
            "Name: 'value #nospace  '\nDescription: |\n  text #nospace  \n  #literal  \n";

        let formatted = preserve(input, canonical, 0).unwrap();

        assert_eq!(
            formatted,
            "Name: 'value #nospace  ' # name\nDescription: | # description\n  text #nospace  \n  #literal  \n# final note\n#\n"
        );
        assert_eq!(
            serde_saphyr::from_str::<serde_json::Value>(input).unwrap(),
            serde_saphyr::from_str::<serde_json::Value>(&formatted).unwrap(),
        );
        assert_eq!(preserve(&formatted, canonical, 0).unwrap(), formatted);
    }

    #[test]
    fn comments_follow_sorted_scalar_sequences_and_nested_fields() {
        let input = "Tags:\n- zulu # last tag\n# first tag\n- alpha\nSwitches: # options\n  # silent option\n  Silent: /S # silent\n  Custom: /C # custom\n";
        let canonical = "Tags:\n- alpha\n- zulu\nSwitches:\n  Custom: /C\n  Silent: /S\n";

        let formatted = preserve(input, canonical, 0).unwrap();

        assert_eq!(
            formatted,
            "Tags:\n# first tag\n- alpha\n- zulu # last tag\nSwitches: # options\n  Custom: /C # custom\n  # silent option\n  Silent: /S # silent\n"
        );
        assert_eq!(preserve(&formatted, canonical, 0).unwrap(), formatted);
    }

    #[test]
    fn keeps_comments_on_fields_omitted_by_serialization() {
        let input = "Name: Example\n# removed field\nUnknown: value # explanation\n# final note\n";
        let canonical = "Name: Example\n";

        let formatted = preserve(input, canonical, 0).unwrap();

        assert_eq!(
            formatted,
            "Name: Example\n# removed field\n# explanation\n# final note\n"
        );
        assert_eq!(preserve(&formatted, canonical, 0).unwrap(), formatted);
    }

    #[test]
    fn distinguishes_sequence_items_with_optional_fields() {
        let input = "Installers:\n- Architecture: x64 # scoped\n  Scope: machine\n- Architecture: x64 # unscoped\n";
        let canonical = "Installers:\n- Architecture: x64\n- Architecture: x64\n  Scope: machine\n";

        let formatted = preserve(input, canonical, 0).unwrap();

        assert_eq!(
            formatted,
            "Installers:\n- Architecture: x64 # unscoped\n- Architecture: x64 # scoped\n  Scope: machine\n"
        );
        assert_eq!(preserve(&formatted, canonical, 0).unwrap(), formatted);
    }
}
