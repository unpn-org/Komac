//! StdUtils operations for the default installer invocation.
//!
//! The default invocation has no command-line switches.

use std::borrow::Cow;

use typed_path::{Utf8Component, Utf8WindowsPath};

fn normalize(path: &str) -> Option<String> {
    let path = Utf8WindowsPath::new(path);
    let symbolic = path.components().next().is_some_and(|part| {
        let part = part.as_str();
        (part.starts_with('%') && part.ends_with('%')) || part.starts_with('$')
    });
    if !path.is_absolute() && !symbolic {
        return None;
    }
    let value = path.normalize().into_string();
    Some(keep_drive_root(
        value.trim_end_matches(['\\', '/']).to_owned(),
    ))
}

fn keep_drive_root(mut value: String) -> String {
    if value.len() == 2 && value.as_bytes()[0].is_ascii_alphabetic() && value.ends_with(':') {
        value.push('\\');
    }
    value
}

pub fn call<'a>(function: &str, stack: &mut Vec<Cow<'a, str>>) -> bool {
    let required = match function {
        "GetParameter" => 2,
        "TestParameter" | "GetAllParameters" | "ParameterStr" | "NormalizePath"
        | "GetParentPath" => 1,
        "ParameterCnt" => 0,
        _ => return false,
    };
    if stack.len() < required {
        return false;
    }
    let output = match function {
        "GetParameter" => stack.last().unwrap().trim().to_owned(),
        "TestParameter" => "false".to_owned(),
        "GetAllParameters" => String::new(),
        "ParameterCnt" => "0".to_owned(),
        "ParameterStr" => "error".to_owned(),
        "NormalizePath" | "GetParentPath" => {
            let Some(normalized) = normalize(stack.last().unwrap()) else {
                return false;
            };
            if function == "GetParentPath" {
                if normalized.ends_with('\\') {
                    String::new()
                } else {
                    normalized
                        .rsplit_once(['\\', '/'])
                        .map(|(parent, _)| {
                            keep_drive_root(parent.trim_end_matches(['\\', '/']).to_owned())
                        })
                        .unwrap_or_default()
                }
            } else {
                normalized
            }
        }
        _ => unreachable!(),
    };
    stack.truncate(stack.len() - required);
    stack.push(Cow::Owned(output));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_parameters_consume_arguments_without_corrupting_the_stack() {
        let mut stack = vec![
            Cow::Borrowed("sentinel"),
            Cow::Borrowed("D"),
            Cow::Borrowed(" fallback "),
        ];
        assert!(call("GetParameter", &mut stack));
        assert_eq!(stack, ["sentinel", "fallback"]);
        stack.pop();
        stack.push(Cow::Borrowed("updated"));
        assert!(call("TestParameter", &mut stack));
        assert_eq!(stack, ["sentinel", "false"]);
        stack.pop();
        stack.push(Cow::Borrowed("0"));
        assert!(call("GetAllParameters", &mut stack));
        assert_eq!(stack, ["sentinel", ""]);
    }

    #[test]
    fn path_helpers_use_windows_paths_and_preserve_drive_roots() {
        for (input, expected) in [
            (r"C:\parent\child\", r"C:\parent"),
            (r"C:\child", r"C:\"),
            (r"C:\", ""),
            (r"%LocalAppData%\Programs\app", r"%LocalAppData%\Programs"),
        ] {
            let mut stack = vec![Cow::Borrowed(input)];
            assert!(call("GetParentPath", &mut stack));
            assert_eq!(stack[0], expected, "{input}");
        }
        let mut stack = vec![Cow::Borrowed(r"C:\parent\.\child\..\")];
        assert!(call("NormalizePath", &mut stack));
        assert_eq!(stack[0], r"C:\parent");
    }

    #[test]
    fn unmodeled_calls_and_missing_arguments_leave_the_stack_unchanged() {
        let mut stack = vec![Cow::Borrowed("relative")];
        assert!(!call("GetParentPath", &mut stack));
        assert!(!call("ExecShellAsUser", &mut stack));
        assert!(!call("GetParameter", &mut stack));
        assert_eq!(stack, ["relative"]);
    }
}
