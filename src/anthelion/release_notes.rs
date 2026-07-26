use color_eyre::eyre::Report;
use napi_derive::napi;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

use super::error::AnthelionError;
use crate::{github::graphql::types::Html, traits::html_to_plain_text};

/// Convert HTML or Markdown release notes to plain text without blocking the JavaScript event loop.
#[napi]
pub async fn release_notes_to_plain_text(
    content: String,
    #[napi(ts_arg_type = "'markdown' | 'html'")] format: String,
) -> napi::Result<Option<String>> {
    let html = match format.as_str() {
        "html" => true,
        "markdown" => false,
        _ => {
            return Err(
                AnthelionError::invalid(format!("Invalid release-note format {format:?}")).into(),
            );
        }
    };

    tokio::task::spawn_blocking(move || {
        if html {
            html_to_plain_text(&Html::new(content))
        } else {
            markdown_to_plain_text(&content)
        }
    })
    .await
    .map_err(|error| {
        AnthelionError::Failure(Report::from(error).wrap_err("Release-note conversion task failed"))
            .into()
    })
}

fn markdown_to_plain_text(markdown: &str) -> Option<String> {
    let mut text = String::with_capacity(markdown.len());
    let mut seen_heading = false;

    for event in Parser::new_ext(markdown, Options::all()) {
        match event {
            Event::Start(Tag::Heading { .. }) => {
                if seen_heading && !text.ends_with("\n\n") {
                    if !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push('\n');
                }
                seen_heading = true;
            }
            Event::Start(Tag::Item) => {
                if !text.ends_with('\n') && !text.is_empty() {
                    text.push('\n');
                }
                text.push_str("- ");
            }
            Event::Text(content)
            | Event::Code(content)
            | Event::Html(content)
            | Event::InlineHtml(content) => text.push_str(&content),
            Event::SoftBreak | Event::HardBreak => text.push('\n'),
            Event::Rule if !text.ends_with('\n') => text.push('\n'),
            Event::TaskListMarker(checked) => {
                text.push_str(if checked { "[x] " } else { "[ ] " });
            }
            Event::End(tag)
                if matches!(
                    tag,
                    TagEnd::Paragraph
                        | TagEnd::Heading(..)
                        | TagEnd::BlockQuote(..)
                        | TagEnd::CodeBlock
                        | TagEnd::Item
                        | TagEnd::List(..)
                        | TagEnd::Table
                        | TagEnd::TableHead
                        | TagEnd::TableRow
                ) && !text.ends_with('\n') =>
            {
                text.push('\n');
            }
            _ => {}
        }
    }

    let start = text.len() - text.trim_start().len();
    let end = text.trim_end().len();
    if start >= end {
        return None;
    }

    text.truncate(end);
    text.drain(..start);
    Some(text)
}

#[cfg(test)]
mod tests {
    use winget_types::locale::ReleaseNotes;

    use super::markdown_to_plain_text;
    use crate::{
        github::graphql::types::Html,
        traits::{FromHtml, html_to_plain_text},
    };

    #[test]
    fn html_conversion_preserves_versions_beyond_manifest_limit() {
        let html = Html::new(format!(
            "<h2>Prerelease</h2><ul>{}</ul><h2>6.5.7</h2><ul><li>Stable release fix.</li></ul>",
            "<li>Earlier release change.</li>".repeat(600)
        ));
        let text = html_to_plain_text(&html).unwrap();
        assert!(text.find("6.5.7").unwrap() > 10_000);
        assert!(text.ends_with("Stable release fix."));

        let manifest_notes = ReleaseNotes::from_html(&html).unwrap().to_string();
        assert!(manifest_notes.len() <= 10_000);
        assert!(!manifest_notes.contains("6.5.7"));
    }

    #[test]
    fn html_conversion_keeps_existing_formatting() {
        let html = Html::new("<h2>Changes</h2><ul><li>Fast</li><li>Reliable</li></ul>".to_owned());
        assert_eq!(
            html_to_plain_text(&html),
            Some(ReleaseNotes::from_html(&html).unwrap().to_string())
        );
        assert_eq!(html_to_plain_text(&Html::new("<p> </p>".to_owned())), None);
    }

    #[test]
    fn formats_markdown() {
        assert_eq!(
            markdown_to_plain_text("# Changes\n\n- Fast\n- Reliable\n"),
            Some("Changes\n- Fast\n- Reliable".to_owned()),
        );
    }
}
