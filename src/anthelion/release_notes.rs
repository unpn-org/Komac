use color_eyre::eyre::Report;
use napi_derive::napi;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use winget_types::locale::ReleaseNotes;

use super::error::AnthelionError;
use crate::{github::graphql::types::Html, traits::FromHtml};

/// Convert HTML or Markdown release notes to plain text without blocking the JavaScript event loop.
#[napi]
pub async fn release_notes_to_plain_text(
    content: String,
    #[napi(ts_arg_type = "'markdown' | 'html'")] format: String,
) -> napi::Result<Option<String>> {
    let format = match format.as_str() {
        "html" => ReleaseNotesFormat::Html,
        "markdown" => ReleaseNotesFormat::Markdown,
        _ => {
            return Err(
                AnthelionError::invalid(format!("Invalid release-note format {format:?}")).into(),
            );
        }
    };

    tokio::task::spawn_blocking(move || match format {
        ReleaseNotesFormat::Html => {
            ReleaseNotes::from_html(&Html::new(content)).map(|notes| notes.to_string())
        }
        ReleaseNotesFormat::Markdown => markdown_to_plain_text(&content),
    })
    .await
    .map_err(|error| {
        AnthelionError::failure(Report::from(error).wrap_err("Release-note conversion task failed"))
            .into()
    })
}

enum ReleaseNotesFormat {
    Markdown,
    Html,
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
    use super::markdown_to_plain_text;

    #[test]
    fn formats_markdown() {
        assert_eq!(
            markdown_to_plain_text("# Changes\n\n- Fast\n- Reliable\n"),
            Some("Changes\n- Fast\n- Reliable".to_owned()),
        );
    }
}
