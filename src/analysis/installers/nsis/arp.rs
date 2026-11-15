//! Identity evidence for web installers whose simulation stops at a download.
//! Never execute unreachable writes or assign their hive/scope to the result.
use std::collections::BTreeMap;

use winget_types::installer::{AppsAndFeaturesEntries, AppsAndFeaturesEntry};

use super::{entry::Entry, registry::Registry};

pub fn from_literal_writes(
    entries: &[Entry],
    literal: impl Fn(i32) -> Option<String>,
) -> AppsAndFeaturesEntries {
    let mut keys = BTreeMap::<String, (String, BTreeMap<String, Option<String>>)>::new();
    for entry in entries {
        let Entry::WriteReg {
            root,
            key_name,
            value_name,
            value,
            r#type,
            ..
        } = entry
        else {
            continue;
        };
        let root = root.resolve(false, 0);
        if !root.is_current_user() && !root.is_local_machine() {
            continue;
        }
        let Some(key) = literal(key_name.get()) else {
            continue;
        };
        let Some(code) = Registry::uninstall_product_code(&key) else {
            continue;
        };
        let (_, fields) = keys
            .entry(key.to_ascii_lowercase())
            .or_insert_with(|| (code.to_owned(), BTreeMap::new()));
        let Some(name) = literal(value_name.get()) else {
            return AppsAndFeaturesEntries::default();
        };
        let name = name.to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "displayname" | "displayversion" | "publisher"
        ) {
            continue;
        }
        let value = (r#type.is_string() || r#type.is_expanded_string())
            .then(|| literal(value.get()))
            .flatten()
            .filter(|value| !value.is_empty());
        fields
            .entry(name)
            .and_modify(|existing| {
                // A conflicting or dynamic write invalidates the field, even when
                // another branch contains a plausible literal for the same name.
                if existing.as_ref() != value.as_ref() {
                    *existing = None;
                }
            })
            .or_insert(value);
    }
    // With multiple product keys, an unreachable prerequisite's identity cannot
    // be distinguished from the primary application without interpreting paths.
    if keys.len() != 1 {
        return AppsAndFeaturesEntries::default();
    }
    let (_, (code, mut fields)) = keys.pop_first().unwrap();
    let name = fields.remove("displayname").flatten();
    let version = fields.remove("displayversion").flatten();
    let publisher = fields.remove("publisher").flatten();
    if name.is_none() && version.is_none() && publisher.is_none() {
        return AppsAndFeaturesEntries::default();
    }
    std::iter::once(
        AppsAndFeaturesEntry::builder()
            .product_code(code)
            .maybe_display_name(name)
            .maybe_display_version(version)
            .maybe_publisher(publisher)
            .build(),
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use zerocopy::I32;

    use super::*;
    use crate::analysis::installers::nsis::registry::{RegRoot, RegType};

    const TEXT: &[Option<&str>] = &[
        Some(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Test.App"),
        Some("DisplayName"),
        None,
        Some("DisplayVersion"),
        Some("2026.10.4"),
        Some("Publisher"),
        Some("Bitwarden Inc."),
        Some("Conflicting value"),
        Some(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Other.App"),
        Some(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Test.App\Child"),
    ];

    fn write(key: i32, name: i32, value: i32) -> Entry {
        Entry::WriteReg {
            root: RegRoot::SHELL_CONTEXT,
            key_name: I32::new(key),
            value_name: I32::new(name),
            value: I32::new(value),
            r#type: RegType::String,
            sub_type: RegType::None,
        }
    }

    fn read(entries: &[Entry]) -> AppsAndFeaturesEntries {
        from_literal_writes(entries, |offset| {
            TEXT.get(offset as usize)
                .copied()
                .flatten()
                .map(str::to_owned)
        })
    }

    #[test]
    fn recovers_literal_identity_and_omits_dynamic_display_name() {
        let entries = read(&[write(0, 1, 2), write(0, 3, 4), write(0, 5, 6)]);
        let entry = entries.iter().next().unwrap();
        assert_eq!(entry.product_code(), Some("Test.App"));
        assert_eq!(entry.display_name(), None);
        assert_eq!(entry.publisher(), Some("Bitwarden Inc."));
        assert_eq!(
            entry.display_version().map(ToString::to_string).as_deref(),
            Some("2026.10.4")
        );
    }

    #[test]
    fn conflicting_and_dynamic_writes_cannot_become_facts() {
        for value in [2, 7] {
            let entries = read(&[
                write(0, 5, 6),
                write(0, 3, 4),
                write(0, 3, value),
                write(0, 3, 4),
            ]);
            let entry = entries.iter().next().unwrap();
            assert_eq!(entry.display_version(), None);
            assert_eq!(entry.publisher(), Some("Bitwarden Inc."));
        }
    }

    #[test]
    fn rejects_ambiguous_keys_uninstall_subkeys_and_unknown_fields() {
        assert!(read(&[write(0, 5, 6), write(8, 5, 6)]).is_empty());
        assert!(read(&[write(9, 5, 6)]).is_empty());
        assert!(read(&[write(0, 5, 6), write(0, 2, 4)]).is_empty());
        assert!(read(&[write(0, 1, 2)]).is_empty());
    }
}
