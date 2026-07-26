use std::{collections::HashMap, fmt::Write};

use color_eyre::eyre::Report;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::{Map, Value};
use serde_saphyr::{
    DefaultMessageFormatter, DuplicateKeyPolicy, MessageFormatter,
    granit_parser::{ErrorKind, Event, Marker, Parser, ScalarStyle, ScanError, Span},
};

use super::error::AnthelionError;

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1_000_000;

type ParseResult<T> = std::result::Result<T, ParseError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRange {
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ParseError {
    message: String,
    code: &'static str,
    range: Option<SourceRange>,
}

impl ParseError {
    fn new(message: impl Into<String>, code: &'static str, range: SourceRange) -> Self {
        Self {
            message: message.into(),
            code,
            range: Some(range),
        }
    }

    fn at_span(input: &str, message: impl Into<String>, code: &'static str, span: &Span) -> Self {
        Self::new(
            message,
            code,
            SourceRange {
                start: marker_byte_offset(input, &span.start),
                end: marker_byte_offset(input, &span.end),
            },
        )
    }

    fn from_scan_error(input: &str, error: ScanError) -> Self {
        let code = match error.kind() {
            ErrorKind::UnknownAnchor => "BAD_ALIAS",
            ErrorKind::MultipleDocumentsUnsupported => "MULTIPLE_DOCS",
            ErrorKind::TooManyComments | ErrorKind::AnchorCountOverflow => "RESOURCE_EXHAUSTION",
            _ => "UNEXPECTED_TOKEN",
        };
        Self::new(
            error.to_string(),
            code,
            SourceRange::from_marker(input, error.marker()),
        )
    }

    fn from_serde_error(input: &str, error: serde_saphyr::Error) -> Self {
        let error = error.without_snippet();
        let code = match error {
            serde_saphyr::Error::DuplicateMappingKey { .. } => "DUPLICATE_KEY",
            serde_saphyr::Error::MultipleDocuments { .. } => "MULTIPLE_DOCS",
            serde_saphyr::Error::UnknownAnchor { .. } => "BAD_ALIAS",
            serde_saphyr::Error::Budget { .. } => "RESOURCE_EXHAUSTION",
            _ => "UNEXPECTED_TOKEN",
        };
        let range = error
            .location()
            .and_then(|location| SourceRange::from_location(input, location))
            .or_else(|| {
                Parser::new_from_str(input)
                    .find_map(|event| event.err())
                    .map(|error| SourceRange::from_marker(input, error.marker()))
            });

        Self {
            message: DefaultMessageFormatter.format_message(error).into_owned(),
            code,
            range,
        }
    }
}

impl SourceRange {
    fn from_marker(input: &str, marker: &Marker) -> Self {
        let start = marker_byte_offset(input, marker);
        let end = input[start..]
            .chars()
            .next()
            .map_or(start, |character| start + character.len_utf8());

        Self { start, end }
    }

    fn from_location(input: &str, location: serde_saphyr::Location) -> Option<Self> {
        let span = location.span();
        let bom_len = usize::from(input.starts_with('\u{feff}')) * '\u{feff}'.len_utf8();
        let source = &input[bom_len..];
        let start = usize::try_from(span.byte_offset()?).ok()?;
        let end = start.checked_add(usize::try_from(span.byte_len()?).ok()?)?;

        (end <= source.len()).then_some(Self {
            start: start + bom_len,
            end: end + bom_len,
        })
    }
}

fn marker_byte_offset(input: &str, marker: &Marker) -> usize {
    marker
        .byte_offset()
        .filter(|offset| *offset <= input.len() && input.is_char_boundary(*offset))
        .unwrap_or(input.len())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourcePosition {
    offset: u32,
    line: u32,
    column: u32,
}

fn source_position(input: &str, byte_offset: usize) -> SourcePosition {
    let mut offset = 0_u32;
    let mut line = 1_u32;
    let mut column = 1_u32;
    let mut previous_was_carriage_return = false;

    for character in input[..byte_offset].chars() {
        let width = character.len_utf16() as u32;
        offset += width;

        match character {
            '\r' => {
                line += 1;
                column = 1;
            }
            '\n' if previous_was_carriage_return => {}
            '\n' => {
                line += 1;
                column = 1;
            }
            _ => column += width,
        }

        previous_was_carriage_return = character == '\r';
    }

    SourcePosition {
        offset,
        line,
        column,
    }
}

fn create_yaml_error<'env>(
    env: &'env Env,
    input: &str,
    error: ParseError,
) -> napi::Result<Object<'env>> {
    let ParseError {
        message,
        code,
        range,
    } = error;
    let mut object = env.create_error(Error::new(Status::InvalidArg, message))?;
    object.set("name", "YAMLParseError")?;
    object.set("code", code)?;

    if let Some(range) = range {
        let start = source_position(input, range.start);
        let end = source_position(input, range.end);
        object.set("pos", [start.offset, end.offset])?;

        let mut start_line = Object::new(env)?;
        start_line.set("line", start.line)?;
        start_line.set("col", start.column)?;
        let mut end_line = Object::new(env)?;
        end_line.set("line", end.line)?;
        end_line.set("col", end.column)?;
        object.set("linePos", [start_line, end_line])?;

        let mut start_location = Object::new(env)?;
        start_location.set("offset", start.offset)?;
        start_location.set("line", start.line)?;
        start_location.set("column", start.column)?;
        let mut end_location = Object::new(env)?;
        end_location.set("offset", end.offset)?;
        end_location.set("line", end.line)?;
        end_location.set("column", end.column)?;
        let mut location = Object::new(env)?;
        location.set("start", start_location)?;
        location.set("end", end_location)?;
        object.set("location", location)?;
    }

    Ok(object)
}

enum Collection {
    Sequence {
        values: Vec<Value>,
        anchor: usize,
        span: Span,
        first_node: usize,
    },
    Mapping {
        values: Map<String, Value>,
        key: Option<String>,
        anchor: usize,
        span: Span,
        first_node: usize,
    },
}

struct FailsafeParser<'input> {
    input: &'input str,
    anchors: HashMap<usize, (Value, usize)>,
    nodes: usize,
}

impl<'input> FailsafeParser<'input> {
    fn parse(input: &'input str) -> ParseResult<Value> {
        let mut parser = Self {
            input,
            anchors: HashMap::new(),
            nodes: 0,
        };
        let mut collections = Vec::new();
        let mut document = None;
        let mut has_document = false;

        for event in Parser::new_from_str(input) {
            let (event, span) = event.map_err(|error| ParseError::from_scan_error(input, error))?;

            if matches!(
                &event,
                Event::Scalar(..)
                    | Event::SequenceStart(..)
                    | Event::MappingStart(..)
                    | Event::Alias(..)
            ) && collections.len() >= MAX_DEPTH
            {
                return Err(ParseError::at_span(
                    input,
                    format!("YAML nesting exceeds the limit of {MAX_DEPTH}"),
                    "RESOURCE_EXHAUSTION",
                    &span,
                ));
            }

            match event {
                Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {
                }
                Event::DocumentStart(..) if has_document => {
                    return Err(ParseError::at_span(
                        input,
                        "source contains multiple YAML documents",
                        "MULTIPLE_DOCS",
                        &span,
                    ));
                }
                Event::DocumentStart(..) => has_document = true,
                Event::Scalar(value, style, anchor, _) => {
                    parser.add_nodes(1, &span)?;
                    let value = if value == "~" && style == ScalarStyle::Plain && span.is_empty() {
                        Value::String(String::new())
                    } else {
                        Value::String(value.into_owned())
                    };
                    parser.store_anchor(anchor, &value, 1);
                    parser.push_value(value, span, &mut collections, &mut document)?;
                }
                Event::SequenceStart(_, anchor, _) => {
                    let first_node = parser.nodes;
                    parser.add_nodes(1, &span)?;
                    collections.push(Collection::Sequence {
                        values: Vec::new(),
                        anchor,
                        span,
                        first_node,
                    });
                }
                Event::SequenceEnd => {
                    let Some(Collection::Sequence {
                        values,
                        anchor,
                        span,
                        first_node,
                    }) = collections.pop()
                    else {
                        return Err(ParseError::at_span(
                            input,
                            "unexpected sequence end",
                            "UNEXPECTED_TOKEN",
                            &span,
                        ));
                    };
                    let value = Value::Array(values);
                    parser.store_anchor(anchor, &value, parser.nodes - first_node);
                    parser.push_value(value, span, &mut collections, &mut document)?;
                }
                Event::MappingStart(_, anchor, _) => {
                    let first_node = parser.nodes;
                    parser.add_nodes(1, &span)?;
                    collections.push(Collection::Mapping {
                        values: Map::new(),
                        key: None,
                        anchor,
                        span,
                        first_node,
                    });
                }
                Event::MappingEnd => {
                    let Some(Collection::Mapping {
                        values,
                        anchor,
                        span,
                        first_node,
                        ..
                    }) = collections.pop()
                    else {
                        return Err(ParseError::at_span(
                            input,
                            "unexpected mapping end",
                            "UNEXPECTED_TOKEN",
                            &span,
                        ));
                    };
                    let value = Value::Object(values);
                    parser.store_anchor(anchor, &value, parser.nodes - first_node);
                    parser.push_value(value, span, &mut collections, &mut document)?;
                }
                Event::Alias(anchor) => {
                    let Some((alias, nodes)) = parser.anchors.get(&anchor).cloned() else {
                        return Err(ParseError::at_span(
                            input,
                            format!("alias refers to unknown anchor {anchor}"),
                            "BAD_ALIAS",
                            &span,
                        ));
                    };
                    parser.add_nodes(nodes, &span)?;
                    parser.push_value(alias, span, &mut collections, &mut document)?;
                }
                event => {
                    return Err(ParseError::at_span(
                        input,
                        format!("unexpected YAML event {event:?}"),
                        "UNEXPECTED_TOKEN",
                        &span,
                    ));
                }
            }
        }

        Ok(document.unwrap_or(Value::Null))
    }

    fn push_value(
        &self,
        value: Value,
        span: Span,
        collections: &mut [Collection],
        document: &mut Option<Value>,
    ) -> ParseResult<()> {
        match collections.last_mut() {
            Some(Collection::Sequence { values, .. }) => values.push(value),
            Some(Collection::Mapping { values, key, .. }) => {
                if let Some(key) = key.take() {
                    values.insert(key, value);
                } else {
                    let key_value = stringify_key(value);
                    if values.contains_key(&key_value) {
                        return Err(ParseError::at_span(
                            self.input,
                            format!(
                                "duplicate mapping key: {key_value} at line {} column {}",
                                span.start.line(),
                                span.start.col() + 1,
                            ),
                            "DUPLICATE_KEY",
                            &span,
                        ));
                    }
                    *key = Some(key_value);
                }
            }
            None if document.is_none() => *document = Some(value),
            None => {
                return Err(ParseError::at_span(
                    self.input,
                    "unexpected YAML value",
                    "UNEXPECTED_TOKEN",
                    &span,
                ));
            }
        }

        Ok(())
    }

    fn add_nodes(&mut self, nodes: usize, span: &Span) -> ParseResult<()> {
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .filter(|nodes| *nodes <= MAX_NODES)
            .ok_or_else(|| {
                ParseError::at_span(
                    self.input,
                    format!("YAML node count exceeds the limit of {MAX_NODES}"),
                    "RESOURCE_EXHAUSTION",
                    span,
                )
            })?;
        Ok(())
    }

    fn store_anchor(&mut self, anchor: usize, value: &Value, nodes: usize) {
        if anchor != 0 {
            self.anchors.insert(anchor, (value.clone(), nodes));
        }
    }
}

fn stringify_key(value: Value) -> String {
    fn write_value(value: Value, output: &mut String) {
        match value {
            Value::Null => {}
            Value::Bool(value) => write!(output, "{value}").unwrap(),
            Value::Number(value) => write!(output, "{value}").unwrap(),
            Value::String(value) => output.push_str(&value),
            Value::Array(values) => {
                output.push_str("[ ");
                for (index, value) in values.into_iter().enumerate() {
                    if index != 0 {
                        output.push_str(", ");
                    }
                    write_value(value, output);
                }
                output.push_str(" ]");
            }
            Value::Object(values) => {
                output.push_str("{ ");
                for (index, (key, value)) in values.into_iter().enumerate() {
                    if index != 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&key);
                    output.push_str(": ");
                    write_value(value, output);
                }
                output.push_str(" }");
            }
        }
    }

    match value {
        Value::String(value) => value,
        value => {
            let mut output = String::new();
            write_value(value, &mut output);
            output
        }
    }
}

fn parse_value(input: &str, failsafe: bool) -> ParseResult<Value> {
    if failsafe {
        FailsafeParser::parse(input)
    } else {
        serde_saphyr::from_str_with_options(
            input,
            serde_saphyr::options! {
                duplicate_keys: DuplicateKeyPolicy::Error,
            },
        )
        .map_err(|error| ParseError::from_serde_error(input, error))
    }
}

/// Parse a YAML document into a JavaScript value.
///
/// The core schema resolves YAML scalar types. The failsafe schema preserves all scalars as
/// strings. Duplicate mapping keys are rejected in both modes.
///
/// # Errors
///
/// Throws a `YAMLParseError` if the input is not a single valid YAML document or contains
/// duplicate mapping keys. The error includes `code`, `pos`, `linePos`, and `location` properties.
#[napi(ts_return_type = "unknown")]
pub fn parse_yaml(
    env: Env,
    input: String,
    #[napi(ts_arg_type = "'core' | 'failsafe'")] schema: Option<String>,
) -> napi::Result<Unknown<'static>> {
    let failsafe = match schema.as_deref() {
        None | Some("core") => false,
        Some("failsafe") => true,
        Some(schema) => {
            return Err(AnthelionError::invalid(format!("Invalid YAML schema {schema:?}")).into());
        }
    };
    let value = match parse_value(&input, failsafe) {
        Ok(value) => value,
        Err(error) => {
            let object = create_yaml_error(&env, &input, error)?;
            return Err(Error::from((&object).into_unknown(&env)?));
        }
    };
    // V8's JSON parser is substantially faster for large mappings than constructing each
    // property through N-API one at a time.
    let json = serde_json::to_string(&value)
        .map_err(|error| AnthelionError::failure(Report::from(error)))?;
    let global = env.get_global()?;
    let json_object: Object = global.get_named_property("JSON")?;
    let parse: Function<String, Unknown<'static>> = json_object.get_named_property("parse")?;
    parse.call(json)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{SourcePosition, SourceRange, parse_value, source_position};

    #[test]
    fn parses_core_schema_scalars() {
        assert_eq!(
            parse_value("enabled: true\ncount: 3\n", false).unwrap(),
            json!({ "enabled": true, "count": 3 }),
        );
    }

    #[test]
    fn preserves_failsafe_scalars() {
        assert_eq!(
            parse_value(
                "null: null\ntilde: ~\nbool: true\nfloat: 1.0\nleading: 001\nempty:\nitems: [1, true]\n",
                true,
            )
            .unwrap(),
            json!({
                "null": "null",
                "tilde": "~",
                "bool": "true",
                "float": "1.0",
                "leading": "001",
                "empty": "",
                "items": ["1", "true"],
            }),
        );
    }

    #[test]
    fn rejects_duplicate_keys() {
        let input = "key: first\nkey: second\n";
        let expected_range = Some(SourceRange { start: 11, end: 14 });

        let core_error = parse_value(input, false).unwrap_err();
        assert_eq!(core_error.code, "DUPLICATE_KEY");
        assert!(!core_error.message.contains('\n'));
        assert_eq!(core_error.range, expected_range);

        let failsafe_error = parse_value(input, true).unwrap_err();
        assert_eq!(failsafe_error.code, "DUPLICATE_KEY");
        assert_eq!(failsafe_error.range, expected_range);
    }

    #[test]
    fn resolves_failsafe_aliases() {
        assert_eq!(
            parse_value("base: &base\n  version: 1.0\ncopy: *base\n", true).unwrap(),
            json!({
                "base": { "version": "1.0" },
                "copy": { "version": "1.0" },
            }),
        );
    }

    #[test]
    fn handles_empty_failsafe_documents() {
        assert_eq!(parse_value("", true).unwrap(), Value::Null,);
        assert_eq!(
            parse_value("---", true).unwrap(),
            Value::String(String::new()),
        );
    }

    #[test]
    fn rejects_multiple_documents() {
        let input = "---\na: 1\n---\nb: 2\n";

        let core_error = parse_value(input, false).unwrap_err();
        assert_eq!(core_error.code, "MULTIPLE_DOCS");
        assert!(core_error.range.is_some());

        let failsafe_error = parse_value(input, true).unwrap_err();
        assert_eq!(failsafe_error.code, "MULTIPLE_DOCS");
        assert!(failsafe_error.range.is_some());
    }

    #[test]
    fn reports_core_syntax_error_ranges() {
        for (input, expected_line, expected_column) in [
            ("key: value\n\"\"\"\"", 2, 3),
            ("key: value\ninvalid\n", 2, 1),
            ("key: [value\n", 1, 6),
        ] {
            let error = parse_value(input, false).unwrap_err();
            let range = error
                .range
                .expect("syntax error should have a source range");
            let position = source_position(input, range.start);

            assert_eq!(position.line, expected_line);
            assert_eq!(position.column, expected_column);
        }
    }

    #[test]
    fn reports_javascript_source_positions() {
        let input = "😀: value\r\nkey";

        assert_eq!(
            source_position(input, input.find("key").unwrap()),
            SourcePosition {
                offset: 11,
                line: 2,
                column: 1,
            },
        );
    }
}
