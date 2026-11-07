use std::borrow::Cow;

use crate::analysis::installers::nsis::Variables;

/// Answers UAC account queries for an administrative, non-forked installation.
pub fn query(function: &str, variables: &mut Variables<'_>, stack: &mut Vec<Cow<'_, str>>) -> bool {
    let (value, to_stack) = match function {
        "IsAdmin" => ("1", false),
        "_" => match stack.last().map(|value| &**value) {
            Some("2") => ("1", false),
            Some("2s") => ("1", true),
            Some("3") => ("0", false),
            Some("3s") => ("0", true),
            _ => return false,
        },
        _ => return false,
    };
    if function == "_" {
        stack.pop();
    }
    if to_stack {
        stack.push(Cow::Borrowed(value));
    } else {
        variables.insert(0, value);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_consume_the_command_and_return_to_the_requested_location() {
        let mut variables = Variables::new();
        for (command, expected) in [("2", "1"), ("3", "0")] {
            for to_stack in [false, true] {
                variables.insert(0, "saved register");
                let command = format!("{command}{}", if to_stack { "s" } else { "" });
                let mut stack = vec![Cow::Borrowed("saved stack"), Cow::Owned(command)];
                assert!(query("_", &mut variables, &mut stack));
                if to_stack {
                    assert_eq!(variables.get(&0), Some("saved register"));
                    assert_eq!(stack.pop().as_deref(), Some(expected));
                } else {
                    assert_eq!(variables.get(&0), Some(expected));
                }
                assert_eq!(stack, ["saved stack"]);
            }
        }
    }

    #[test]
    fn elevation_and_callbacks_are_not_simulated_as_successful_queries() {
        let mut variables = Variables::new();
        variables.insert(0, "saved");
        for command in ["0", "1", "4", "5", "2bad"] {
            let mut stack = vec![Cow::Borrowed(command)];
            assert!(!query("_", &mut variables, &mut stack));
            assert_eq!(stack, [command]);
            assert_eq!(variables.get(&0), Some("saved"));
        }
    }
}
