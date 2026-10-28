use std::sync::OnceLock;

use napi::bindgen_prelude::{Env, JsObjectValue, Object};
use napi_derive::napi;

use super::error::InvalidArgument;
use crate::github::{set_github_ref, set_upstream};

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Default)]
struct Config {
    github_token: Option<String>,
    dry_run: Option<bool>,
}

pub fn github_token() -> Option<&'static str> {
    CONFIG.get_or_init(Config::default).github_token.as_deref()
}

pub fn dry_run() -> Option<bool> {
    CONFIG.get_or_init(Config::default).dry_run
}

fn get_env(env: &Object, name: &str) -> napi::Result<Option<String>> {
    Ok(env
        .get::<String>(name)?
        .filter(|value| !value.trim().is_empty()))
}

/// Copies configuration from JavaScript's `process.env` into the native binding.
#[napi(module_exports)]
fn configure(env: Env) -> napi::Result<()> {
    let process: Object = env.get_global()?.get_named_property("process")?;
    let process_env: Object = process.get_named_property("env")?;

    if let Some(repository) = get_env(&process_env, "KOMAC_REPOSITORY")? {
        set_upstream(
            repository
                .parse()
                .map_err(|error| InvalidArgument(format!("{error}")))?,
        );
    }

    if let Some(reference) = get_env(&process_env, "KOMAC_GITHUB_REF")? {
        set_github_ref(reference);
    }

    let dry_run = get_env(&process_env, "DRY_RUN")?
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| InvalidArgument("DRY_RUN must be true or false".into()))?;

    let _ = CONFIG.set(Config {
        github_token: get_env(&process_env, "GITHUB_TOKEN")?,
        dry_run,
    });

    Ok(())
}
