mod root;
mod r#type;

use std::{collections::BTreeMap, fmt};

use itertools::Itertools;
pub use root::RegRoot;
pub use r#type::RegType;
use winget_types::installer::Scope;

type Key = String;

type ValueName = String;

pub type Value = String;

type Values = BTreeMap<ValueName, Value>;

type Keys = BTreeMap<Key, Values>;

/// A mock registry for simulating execution of `WriteReg` and `DeleteReg` entries.
///
/// This represents a hierarchical registry structure modeled as:
///
/// - A **Registry root** maps to multiple **Keys** (one-to-many).
/// - Each **Key** maps to multiple **Value names** (one-to-many).
/// - Each **Value name** maps to a single **Value** (one-to-one).
///
/// Hierarchy:
///
/// ```
/// Registry root ─┬─> Key name ─┬─> Value name ──> Value
///                │             └──────────────> ...
///                └────────────> ...
/// ```
#[derive(Clone, Debug)]
pub struct Registry(
    BTreeMap<RegRoot, Keys>,
    BTreeMap<(RegRoot, String, String), RegType>,
);

const CURRENT_VERSION_UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

impl Registry {
    #[inline]
    pub const fn new() -> Self {
        Self(BTreeMap::new(), BTreeMap::new())
    }

    /// Each ARP entry must come from a single immediate child of the uninstall key.
    pub fn uninstall_entries(&self) -> impl Iterator<Item = (RegRoot, &str, &Values)> {
        self.0
            .iter()
            .filter(|(root, _)| root.is_current_user() || root.is_local_machine())
            .flat_map(|(&root, keys)| {
                keys.iter().filter_map(move |(key, values)| {
                    let (parent, product_code) = key.trim_end_matches('\\').rsplit_once('\\')?;
                    (parent.eq_ignore_ascii_case(CURRENT_VERSION_UNINSTALL)
                        && !product_code.is_empty())
                    .then_some((root, product_code, values))
                })
            })
    }

    pub fn uninstall_value<'a>(values: &'a Values, name: &str) -> Option<&'a Value> {
        values.iter().find_map(|(key, value)| {
            (key.eq_ignore_ascii_case(name) && !value.is_empty()).then_some(value)
        })
    }

    pub fn product_code(&self) -> Option<&str> {
        self.uninstall_entries().next().map(|(_, code, _)| code)
    }

    pub fn product_code_scope(&self) -> Option<Scope> {
        self.uninstall_entries().next().and_then(|(root, _, _)| {
            if root.is_current_user() {
                Some(Scope::User)
            } else if root.is_local_machine() {
                Some(Scope::Machine)
            } else {
                None
            }
        })
    }

    /// Inserts the value into the registry.
    ///
    /// If the registry did not have this value name present, [`None`] is returned.
    ///
    /// If the registry did have this value name present, the value is updated, and the old value is
    /// returned.
    pub fn insert_value<K, N, V>(
        &mut self,
        root: RegRoot,
        key: K,
        name: N,
        value: V,
    ) -> Option<Value>
    where
        K: Into<Key>,
        N: Into<ValueName>,
        V: Into<Value>,
    {
        let root = root.resolve(false, 0);
        let key = key.into();
        let name = name.into();
        self.1
            .remove(&(root, key.to_lowercase(), name.to_lowercase()));
        let keys = self.0.entry(root).or_default();
        let key = keys
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(&key))
            .cloned()
            .unwrap_or(key);
        let values = keys.entry(key).or_default();
        let name = values
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(&name))
            .cloned()
            .unwrap_or(name);
        values.insert(name, value.into())
    }

    pub fn key_exists(&self, root: RegRoot, key: &str) -> bool {
        if key.is_empty() {
            return true;
        }
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        self.0.get(&root.resolve(false, 0)).is_some_and(|keys| {
            keys.keys().any(|existing| {
                existing.eq_ignore_ascii_case(key)
                    || existing
                        .get(..prefix.len())
                        .is_some_and(|parent| parent.eq_ignore_ascii_case(&prefix))
            })
        })
    }

    pub fn create_key(&mut self, root: RegRoot, key: &str) {
        let keys = self.0.entry(root.resolve(false, 0)).or_default();
        if !keys
            .keys()
            .any(|existing| existing.eq_ignore_ascii_case(key))
        {
            keys.insert(key.to_owned(), BTreeMap::new());
        }
    }

    pub fn enum_subkey(&self, root: RegRoot, key: &str, index: usize) -> Option<String> {
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{}\\", key.trim_end_matches('\\'))
        };
        let keys = self.0.get(&root.resolve(false, 0))?;
        let mut children = BTreeMap::new();
        for existing in keys.keys() {
            if existing
                .get(..prefix.len())
                .is_some_and(|parent| parent.eq_ignore_ascii_case(&prefix))
            {
                let child = existing[prefix.len()..].split('\\').next()?;
                if !child.is_empty() {
                    children.entry(child.to_ascii_lowercase()).or_insert(child);
                }
            }
        }
        children
            .values()
            .nth(index)
            .map(|child| (*child).to_owned())
    }

    pub fn enum_value_name(&self, root: RegRoot, key: &str, index: usize) -> Option<String> {
        let keys = self.0.get(&root.resolve(false, 0))?;
        let (_, values) = keys
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))?;
        values.keys().nth(index).cloned()
    }

    pub fn insert_typed(
        &mut self,
        root: RegRoot,
        key: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
        kind: RegType,
    ) {
        let root = root.resolve(false, 0);
        let key = key.into();
        let name = name.into();
        self.insert_value(root, key.clone(), name.clone(), value);
        self.1
            .insert((root, key.to_lowercase(), name.to_lowercase()), kind);
    }

    pub fn value_type(&self, root: RegRoot, key: &str, name: &str) -> Option<RegType> {
        self.get_value(root, key, name)?;
        Some(
            self.1
                .get(&(
                    root.resolve(false, 0),
                    key.to_lowercase(),
                    name.to_lowercase(),
                ))
                .copied()
                .unwrap_or(RegType::String),
        )
    }

    pub fn get_value(&self, root: RegRoot, key: &str, name: &str) -> Option<&Value> {
        let root = root.resolve(false, 0);
        let (_, values) = self
            .0
            .get(&root)?
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))?;
        values
            .iter()
            .find_map(|(existing, value)| existing.eq_ignore_ascii_case(name).then_some(value))
    }

    pub fn delete_key(&mut self, root: RegRoot, key: &str, only_if_empty: bool) -> bool {
        let root = root.resolve(false, 0);
        let Some(keys) = self.0.get_mut(&root) else {
            return false;
        };
        let prefix = format!("{}\\", key.trim_end_matches('\\')).to_lowercase();
        if only_if_empty
            && keys.iter().any(|(existing, values)| {
                (existing.eq_ignore_ascii_case(key) && !values.is_empty())
                    || existing.to_lowercase().starts_with(&prefix)
            })
        {
            return false;
        }
        let before = keys.len();
        keys.retain(|existing, _| {
            !existing.eq_ignore_ascii_case(key) && !existing.to_lowercase().starts_with(&prefix)
        });
        let removed = keys.len() != before;
        self.1.retain(|(item_root, item_key, _), _| {
            *item_root != root
                || (!item_key.eq_ignore_ascii_case(key) && !item_key.starts_with(&prefix))
        });
        removed
    }

    /// Removes a key using Windows' case-insensitive registry name comparison.
    pub fn remove_key(&mut self, root: RegRoot, key: &str) -> Option<Values> {
        let root = root.resolve(false, 0);
        let keys = self.0.get_mut(&root)?;
        let key = keys
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(key))?
            .clone();
        self.1.retain(|(item_root, item_key, _), _| {
            *item_root != root || !item_key.eq_ignore_ascii_case(&key)
        });
        keys.remove(&key)
    }

    pub fn remove_value_name(&mut self, root: RegRoot, key: &str, name: &str) -> Option<Value> {
        let root = root.resolve(false, 0);
        let keys = self.0.get_mut(&root)?;
        let (_, values) = keys
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))?;
        let name = values
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(name))?
            .clone();
        self.1
            .remove(&(root, key.to_lowercase(), name.to_lowercase()));
        values.remove(&name)
    }
}

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, (root, keys)) in self.0.iter().with_position() {
            if !position.is_first() {
                writeln!(f)?;
            }

            for (position, (key, values)) in keys.iter().with_position() {
                if !position.is_first() {
                    writeln!(f)?;
                }

                writeln!(f, r"{root}\{key}")?;

                let max_name_len = values.keys().map(ValueName::len).max().unwrap_or_default();

                for (name, value) in values {
                    writeln!(f, "    {name:<max_name_len$} = {value}")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_immediate_subkeys_and_value_names() {
        let mut registry = Registry::new();
        let root = RegRoot::HKEY_CURRENT_USER;
        registry.insert_value(root, r"Software\Parent\First\Leaf", "Value", "data");
        registry.insert_value(root, r"Software\Parent\Other", "OtherValue", "data");
        assert!(registry.key_exists(root, r"software\parent"));
        assert_eq!(
            registry.enum_subkey(root, r"software\parent", 0).as_deref(),
            Some("First")
        );
        assert_eq!(
            registry.enum_subkey(root, r"Software\Parent", 1).as_deref(),
            Some("Other")
        );
        assert_eq!(registry.enum_subkey(root, r"Software\Parent", 2), None);
        assert_eq!(registry.enum_subkey(root, r"Software\Missing", 0), None);
        assert_eq!(
            registry
                .enum_value_name(root, r"Software\Parent\First\Leaf", 0)
                .as_deref(),
            Some("Value")
        );
        assert_eq!(
            registry.enum_value_name(root, r"Software\Parent\First\Leaf", 1),
            None
        );
    }

    #[test]
    fn registry_views_and_value_types_are_independent() {
        let mut registry = Registry::new();
        let root = RegRoot::HKEY_CURRENT_USER;
        registry.insert_typed(root, "Key", "Number", "42", RegType::DWord);
        assert_eq!(
            registry.value_type(root, "KEY", "NUMBER"),
            Some(RegType::DWord)
        );
        registry.insert_value(root, "key", "number", "string");
        assert_eq!(
            registry.value_type(root, "Key", "Number"),
            Some(RegType::String)
        );
        registry.insert_value(RegRoot::HKEY_CURRENT_USER64, "Key", "Number", "64-bit");
        assert_eq!(
            registry
                .get_value(root, "Key", "Number")
                .map(String::as_str),
            Some("string")
        );
        assert_eq!(
            registry
                .get_value(RegRoot::HKEY_CURRENT_USER64, "Key", "Number")
                .map(String::as_str),
            Some("64-bit")
        );
    }

    #[test]
    fn conditional_deletion_keeps_values_and_subkeys() {
        let mut registry = Registry::new();
        let root = RegRoot::HKEY_CURRENT_USER;
        registry.insert_value(root, r"Software\Parent\Child", "DisplayName", "Child");
        assert!(!registry.delete_key(root, r"Software\Parent", true));
        assert!(!registry.delete_key(root, r"Software\Parent\Child", true));
        assert!(registry.delete_key(root, r"software\parent", false));
        assert!(
            registry
                .get_value(root, r"Software\Parent\Child", "DisplayName")
                .is_none()
        );
    }

    #[test]
    fn registry_names_are_case_insensitive_and_last_write_wins() {
        let mut registry = Registry::new();
        let root = RegRoot::HKEY_LOCAL_MACHINE;
        let key = format!(r"{CURRENT_VERSION_UNINSTALL}\Test.App");
        registry.insert_value(root, &*key, "DisplayName", "Old");
        registry.insert_value(root, key.to_lowercase(), "displayname", "New");
        let (_, code, values) = registry.uninstall_entries().next().unwrap();
        assert_eq!(code, "Test.App");
        assert_eq!(
            Registry::uninstall_value(values, "DISPLAYNAME").map(String::as_str),
            Some("New")
        );
        assert_eq!(
            registry.remove_value_name(root, &key.to_lowercase(), "DISPLAYNAME"),
            Some("New".to_owned())
        );
        registry.remove_key(root, &key.to_uppercase()).unwrap();
        assert_eq!(registry.uninstall_entries().count(), 0);
    }
}
