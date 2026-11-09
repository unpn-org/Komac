use std::borrow::Cow;

use super::super::file_system::{FileSystem, RelativeLocation};

/// Model file ACL writes on the permissive simulated administrative filesystem.
/// Stack contracts: Docs/AccessControl/AccessControl.txt in the upstream plugin archive.
pub fn call(function: &str, stack: &mut Vec<Cow<'_, str>>, files: &FileSystem) -> bool {
    let arguments = match function {
        "DisableFileInheritance" => 1,
        "SetOnFile" | "GrantOnFile" => 3,
        _ => return false,
    };
    let option = usize::from(
        arguments == 3
            && stack
                .last()
                .is_some_and(|arg| arg.eq_ignore_ascii_case("/NOINHERIT")),
    );
    let count = arguments + option;
    if stack.len() < count {
        return false;
    }
    let path = &stack[stack.len() - option - 1];
    let error = if !files.exists(&**path, RelativeLocation::Current) {
        Some("File not found in the simulated filesystem")
    } else if arguments == 3 {
        let trustee = &stack[stack.len() - option - 2];
        let permissions = &stack[stack.len() - option - 3];
        if !matches!(&**trustee, "(BU)" | "(AU)" | "(BA)" | "(SY)" | "(WD)") {
            Some("Trustee cannot be resolved in the simulated account")
        } else if !permissions.split('+').all(|permission| {
            matches!(
                permission.trim(),
                "GenericRead"
                    | "GenericWrite"
                    | "GenericExecute"
                    | "FullAccess"
                    | "Delete"
                    | "NULL"
            )
        }) {
            Some("Permissions are not supported by the simulated filesystem")
        } else {
            None
        }
    } else {
        None
    };
    stack.truncate(stack.len() - count);
    if let Some(error) = error {
        stack.push(Cow::Borrowed(error));
        stack.push(Cow::Borrowed("error"));
    } else {
        stack.push(Cow::Borrowed("ok"));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_acl_calls_consume_options_and_return_status_above_saved_values() {
        let mut files = FileSystem::new();
        files
            .create_file(r"$EXEDIR\uninstall.exe", None, 0u64, RelativeLocation::Root)
            .unwrap();
        let mut stack = vec![
            Cow::Borrowed("saved"),
            Cow::Borrowed("GenericRead + GenericExecute"),
            Cow::Borrowed("(BU)"),
            Cow::Borrowed(r"$EXEDIR\uninstall.exe"),
            Cow::Borrowed("/NOINHERIT"),
        ];
        assert!(call("SetOnFile", &mut stack, &files));
        assert_eq!(stack, ["saved", "ok"]);
        stack.pop();
        stack.push(Cow::Borrowed(r"$EXEDIR\uninstall.exe"));
        assert!(call("DisableFileInheritance", &mut stack, &files));
        assert_eq!(stack, ["saved", "ok"]);
        stack.pop();
        stack.extend([
            Cow::Borrowed("FullAccess"),
            Cow::Borrowed("(BA)"),
            Cow::Borrowed(r"$EXEDIR\uninstall.exe"),
        ]);
        assert!(call("GrantOnFile", &mut stack, &files));
        assert_eq!(stack, ["saved", "ok"]);
    }

    #[test]
    fn missing_files_return_error_details_without_consuming_saved_values() {
        let mut stack = vec![Cow::Borrowed("saved"), Cow::Borrowed("missing.exe")];
        assert!(call(
            "DisableFileInheritance",
            &mut stack,
            &FileSystem::new()
        ));
        assert_eq!(stack.pop().as_deref(), Some("error"));
        assert!(stack.pop().unwrap().contains("File not found"));
        assert_eq!(stack, ["saved"]);
    }
}
