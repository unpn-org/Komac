use std::borrow::Cow;

/// Selects the primary installer language using LangDLL's stack convention.
pub fn select(stack: &mut Vec<Cow<'_, str>>, language: u16) -> Option<u16> {
    let mut arguments = stack.iter().rev();
    arguments.next()?; // Window title
    arguments.next()?; // Window text
    let flags = arguments.next()?;
    let automatic = flags.contains('A');
    let codepages = flags.contains('C');
    let fields = if codepages { 3 } else { 2 };
    let count = if automatic {
        let fields_count = arguments.clone().position(|value| value.is_empty())?;
        if fields_count % fields != 0 {
            return None;
        }
        fields_count / fields
    } else {
        flags.trim_end_matches(['C', 'F']).parse::<usize>().ok()?
    };
    if !(1..=256).contains(&count) {
        return None;
    }
    let mut found = false;
    for _ in 0..count {
        arguments.next()?;
        found |= arguments.next()?.parse::<u16>().ok()? == language;
        if codepages {
            arguments.next()?.parse::<u32>().ok()?;
        }
    }
    if automatic && !arguments.next()?.is_empty() {
        return None;
    }
    if flags.contains('F') && count > 1 {
        arguments.next()?.parse::<u32>().ok()?;
        arguments.next()?;
    }
    if !found {
        return None;
    }
    let keep = arguments.len();
    stack.truncate(keep);
    stack.push(Cow::Owned(language.to_string()));
    Some(language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_count_and_codepages_preserve_saved_registers() {
        let mut stack = [
            "saved", "", "1252", "1031", "Deutsch", "1252", "1033", "English", "AC", "Choose",
            "Title",
        ]
        .map(Cow::Borrowed)
        .to_vec();
        assert_eq!(select(&mut stack, 1033), Some(1033));
        assert_eq!(stack, ["saved", "1033"]);
    }

    #[test]
    fn explicit_count_and_font_options_are_consumed() {
        let mut stack = [
            "saved", "Arial", "12", "1031", "Deutsch", "1033", "English", "2F", "Choose", "Title",
        ]
        .map(Cow::Borrowed)
        .to_vec();
        assert_eq!(select(&mut stack, 1031), Some(1031));
        assert_eq!(stack, ["saved", "1031"]);
    }

    #[test]
    fn malformed_or_unavailable_selections_preserve_the_stack() {
        for flags in ["AC", "999999999F", "1"] {
            let mut stack = ["saved", "1031", "Deutsch", flags, "Choose", "Title"]
                .map(Cow::Borrowed)
                .to_vec();
            let original = stack.clone();
            assert_eq!(select(&mut stack, 1033), None);
            assert_eq!(stack, original);
        }
    }
}
