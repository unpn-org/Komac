mod submit_option;

use std::time::Duration;

use color_eyre::{Result, eyre::bail};
pub use submit_option::SubmitOption;
use winget_types::installer::{InstallerManifest, InstallerType, NestedInstallerType};

pub use crate::github::rate_limit::{RateLimit, SPINNER_SLOW_TICK_RATE};
use crate::traits::InstallerManifestExt;

pub const SPINNER_TICK_RATE: Duration = Duration::from_millis(50);

pub fn check_package_type(manifest: &InstallerManifest) -> Result<bool> {
    let (mut has_font, mut has_installer) = (false, false);

    for installer in manifest.inherit_manifest_properties() {
        if installer.r#type == Some(InstallerType::Font)
            || installer.nested_installer_type == Some(NestedInstallerType::Font)
        {
            has_font = true;
        } else {
            has_installer = true;
        }

        if has_font && has_installer {
            bail!("Application and font installers cannot be mixed in the same manifest");
        }
    }

    Ok(has_font)
}
