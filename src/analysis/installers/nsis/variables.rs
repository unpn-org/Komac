use std::{borrow::Borrow, collections::HashMap, fmt, hash::Hash};

use typed_path::Utf8WindowsPathBuf;

use super::strings::{NsisCow, NsisStr, NsisString, PredefinedVar};

// NSIS large-string builds use at most 8192 native code units.
pub(super) const MAX_STRING_LENGTH: usize = 8192;

pub(super) trait NsisStringExt {
    fn push_bounded(&mut self, value: &str);
    fn push_bounded_nsis(&mut self, value: NsisStr<'_>);
}

impl NsisStringExt for NsisString {
    fn push_bounded(&mut self, value: &str) {
        let value = NsisString::from_str(value, self.is_unicode());
        self.push_bounded_nsis(value.as_nsis_str());
    }

    fn push_bounded_nsis(&mut self, value: NsisStr<'_>) {
        let remaining = MAX_STRING_LENGTH.saturating_sub(self.len());
        self.push_nsis_str(value.slice(0..value.len().min(remaining)));
        self.truncate(MAX_STRING_LENGTH);
    }
}

pub(super) fn bound_string(value: NsisCow<'_>) -> NsisCow<'_> {
    if value.len() <= MAX_STRING_LENGTH {
        return value;
    }
    match value {
        NsisCow::Borrowed(value) => NsisCow::Borrowed(value.slice(0..MAX_STRING_LENGTH)),
        NsisCow::Owned(mut value) => {
            value.truncate(MAX_STRING_LENGTH);
            NsisCow::Owned(value)
        }
    }
}

/// The NSIS variables (`$0`-`$9`, `$R0`-`$R9`, predefined variables, and user variables), keyed by
/// index and stored in the installer's native string encoding.
#[derive(Clone)]
pub struct Variables<'data>(HashMap<usize, NsisCow<'data>>);

impl<'data> Variables<'data> {
    /// There are 20 integer registers before predefined variables
    pub const NUM_REGISTERS: usize = 20;

    pub const NUM_INTERNAL_VARS: usize = Self::NUM_REGISTERS + PredefinedVar::num_vars();

    const INSTALL_DIR_INDEX: usize = Self::NUM_REGISTERS + PredefinedVar::InstDir as usize;

    /// Creates an empty set of variables.
    #[inline]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Returns the value of the variable at `index`, or `None` if it has not been set.
    pub fn get<Q>(&self, index: &Q) -> Option<NsisStr<'_>>
    where
        usize: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.get(index).map(NsisCow::as_nsis_str)
    }

    /// Sets the variable at `index`, returning its previous value if it was set.
    pub fn insert<V>(&mut self, index: usize, variable: V) -> Option<NsisCow<'data>>
    where
        V: Into<NsisCow<'data>>,
    {
        self.0.insert(index, bound_string(variable.into()))
    }

    /// Unsets the variable at `index`, returning its previous value if it was set.
    pub fn remove<Q>(&mut self, index: &Q) -> Option<NsisCow<'data>>
    where
        usize: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.remove(index)
    }

    /// Returns the install directory decoded as a UTF-8 Windows path, if it is set and non-empty.
    pub fn install_dir(&self) -> Option<Utf8WindowsPathBuf> {
        self.get(&Self::INSTALL_DIR_INDEX)
            .filter(|dir| !dir.is_empty())
            .map(|dir| Utf8WindowsPathBuf::from(dir.to_string_lossy().into_owned()))
    }

    /// Sets `$INSTDIR`, returning its previous value if it was set.
    pub fn insert_install_dir<T>(&mut self, install_dir: T) -> Option<NsisCow<'data>>
    where
        T: Into<NsisCow<'data>>,
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
    use super::{MAX_STRING_LENGTH, Variables, NsisString};
    use crate::analysis::installers::nsis::{strings::var::NsVar, version::NsisVersion};

    #[test]
    fn self_appending_variable_stays_bounded() {
        let mut variables = Variables::new();
        variables.insert(0, NsisString::from_str("é", true));

        for iteration in 0..100 {
            let mut expanded = NsisString::new_wide();
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
