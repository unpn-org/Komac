use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    fmt,
    hash::Hash,
};

use typed_path::Utf8WindowsPath;

use super::strings::PredefinedVar;

// NSIS uses fixed-size string buffers (1024 by default, 8192 in large-string builds).
// Use the larger size when simulating installers so variable expansion cannot grow without bound.
pub(super) const MAX_STRING_LENGTH: usize = 8192;

fn bounded_end(value: &str, limit: usize) -> usize {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

pub(super) trait NsisStringExt {
    fn push_bounded(&mut self, value: &str);
}

impl NsisStringExt for String {
    fn push_bounded(&mut self, value: &str) {
        if self.len() < MAX_STRING_LENGTH {
            self.push_str(&value[..bounded_end(value, MAX_STRING_LENGTH - self.len())]);
        }
    }
}

pub(super) fn bound_string<'data>(value: Cow<'data, str>) -> Cow<'data, str> {
    if value.len() <= MAX_STRING_LENGTH {
        return value;
    }

    let end = bounded_end(&value, MAX_STRING_LENGTH);
    match value {
        Cow::Borrowed(value) => Cow::Borrowed(&value[..end]),
        Cow::Owned(mut value) => {
            value.truncate(end);
            Cow::Owned(value)
        }
    }
}

#[derive(Clone)]
pub struct Variables<'data>(HashMap<usize, Cow<'data, str>>);

impl<'data> Variables<'data> {
    /// There are 20 integer registers before predefined variables
    pub const NUM_REGISTERS: usize = 20;

    pub const NUM_INTERNAL_VARS: usize = Self::NUM_REGISTERS + PredefinedVar::num_vars();

    const INSTALL_DIR_INDEX: usize = Self::NUM_REGISTERS + PredefinedVar::InstDir as usize;

    #[inline]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get<Q>(&self, index: &Q) -> Option<&str>
    where
        usize: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.get(index).map(Cow::as_ref)
    }

    pub fn insert<V>(&mut self, index: usize, variable: V) -> Option<Cow<'data, str>>
    where
        V: Into<Cow<'data, str>>,
    {
        self.0.insert(index, bound_string(variable.into()))
    }

    pub fn remove<Q>(&mut self, index: &Q) -> Option<Cow<'data, str>>
    where
        usize: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.remove(index)
    }

    pub fn install_dir(&self) -> Option<&Utf8WindowsPath> {
        self.get(&Self::INSTALL_DIR_INDEX)
            .filter(|&dir| !dir.is_empty())
            .map(Utf8WindowsPath::new)
    }

    pub fn insert_install_dir<T>(&mut self, install_dir: T) -> Option<Cow<'_, str>>
    where
        T: Into<Cow<'data, str>>,
    {
        self.insert(Self::INSTALL_DIR_INDEX, install_dir)
    }
}

impl fmt::Debug for Variables<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_STRING_LENGTH, Variables};
    use crate::analysis::installers::nsis::{strings::var::NsVar, version::NsisVersion};

    #[test]
    fn self_appending_variable_stays_bounded() {
        let mut variables = Variables::new();
        variables.insert(0, "é");

        for iteration in 0..100 {
            let mut expanded = String::new();
            NsVar::resolve(&mut expanded, 0, &variables, NsisVersion::v3());
            NsVar::resolve(&mut expanded, 0, &variables, NsisVersion::v3());
            variables.insert(0, expanded);
            if iteration == 0 {
                assert_eq!(variables.get(&0).unwrap(), "éé");
            }
            assert!(variables.get(&0).unwrap().len() <= MAX_STRING_LENGTH);
        }
        assert_eq!(variables.get(&0).unwrap().len(), MAX_STRING_LENGTH);
    }
}
