use super::{NsisCow, NsisString, PredefinedVar};
use crate::analysis::installers::nsis::{
    variables::{NsisStringExt, Variables},
    version::NsisVersion,
};

pub struct NsVar;

impl NsVar {
    pub fn resolve(
        buf: &mut NsisString,
        index: usize,
        variables: &Variables,
        nsis_version: NsisVersion,
    ) {
        buf.push_bounded_nsis(Self::value(index, variables, nsis_version).as_nsis_str());
    }

    pub fn value<'a>(
        index: usize,
        variables: &'a Variables<'_>,
        nsis_version: NsisVersion,
    ) -> NsisCow<'a> {
        if let Some(value) = variables.get(&index) {
            return NsisCow::Borrowed(value);
        }
        if let Variables::NUM_REGISTERS..Variables::NUM_INTERNAL_VARS = index {
            let mut offset = index - Variables::NUM_REGISTERS;
            if nsis_version == 2.25 && offset >= PredefinedVar::ExePath as usize {
                offset += size_of::<u16>();
            }
            match PredefinedVar::try_from(offset) {
                Ok(PredefinedVar::InstDir) | Err(_) => {}
                Ok(var) => return NsisString::from_str(var.as_str(), true).into(),
            }
        }
        NsisString::new_wide().into()
    }
}
