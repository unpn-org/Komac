use super::PredefinedVar;
use crate::analysis::installers::nsis::{
    variables::{NsisStringExt, Variables},
    version::NsisVersion,
};

pub struct NsVar;

impl NsVar {
    pub fn resolve(
        buf: &mut String,
        index: usize,
        variables: &Variables,
        nsis_version: NsisVersion,
    ) {
        buf.push_bounded(Self::value(index, variables, nsis_version));
    }

    pub fn value<'a>(
        index: usize,
        variables: &'a Variables<'_>,
        nsis_version: NsisVersion,
    ) -> &'a str {
        if let Some(value) = variables.get(&index) {
            return value;
        }
        if let Variables::NUM_REGISTERS..Variables::NUM_INTERNAL_VARS = index {
            let mut offset = index - Variables::NUM_REGISTERS;
            if nsis_version == 2.25 && offset >= PredefinedVar::ExePath as usize {
                offset += size_of::<u16>();
            }
            match PredefinedVar::try_from(offset) {
                Ok(PredefinedVar::InstDir) | Err(_) => {}
                Ok(var) => return var.as_str(),
            }
        }
        ""
    }
}
