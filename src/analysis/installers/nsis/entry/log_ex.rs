use std::borrow::Cow;

/// Consume the documented logging arguments without changing installer registers.
/// LogEx's Init, Write, and Close exports do not push return values.
/// <https://nsis.sourceforge.io/LogEx_plug-in>
pub fn call(function: &str, stack: &mut Vec<Cow<'_, str>>) -> bool {
    let max_options = match function {
        "Init" => 1,
        "Write" => 2,
        "Close" => return true,
        _ => return false,
    };
    let options = stack
        .iter()
        .rev()
        .take(max_options)
        .take_while(|value| {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")
        })
        .count();
    if stack.len() <= options {
        return false;
    }
    stack.truncate(stack.len() - options - 1);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_consumes_only_its_arguments_and_pushes_no_result() {
        for (function, options) in [("Init", 1), ("Write", 2)] {
            for count in 0..=options {
                let mut stack = vec![Cow::Borrowed("saved"), Cow::Borrowed("message or filename")];
                stack.extend((0..count).map(|_| Cow::Borrowed("false")));
                assert!(call(function, &mut stack));
                assert_eq!(stack, ["saved"]);
                assert!(call("Close", &mut stack));
                assert_eq!(stack, ["saved"]);
            }
        }
    }

    #[test]
    fn unsupported_and_missing_arguments_leave_the_stack_unchanged() {
        let mut stack = vec![Cow::Borrowed("saved")];
        assert!(!call("AddFile", &mut stack));
        assert_eq!(stack, ["saved"]);
        let mut stack = vec![Cow::Borrowed("true")];
        assert!(!call("Write", &mut stack));
        assert_eq!(stack, ["true"]);
    }
}
