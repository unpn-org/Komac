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
        if let Variables::NUM_REGISTERS..Variables::NUM_INTERNAL_VARS = index {
            let mut offset = index - Variables::NUM_REGISTERS;
            if nsis_version == 2.25 && offset >= PredefinedVar::ExePath as usize {
                offset += size_of::<u16>();
            }
            match PredefinedVar::try_from(offset) {
                Ok(PredefinedVar::InstDir) => {
                    if let Some(dir) = variables.get(&index) {
                        buf.push_bounded(dir);
                    }
                }
                Ok(var) => buf.push_bounded(var.as_str()),
                Err(_) => {}
            }
        } else if let Some(var) = variables.get(&index) {
            buf.push_bounded(var);
        }
    }
}
