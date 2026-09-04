use std::fs::File;

use jiff::civil::Date;
use winget_types::{Sha256String, installer::Architecture};

use crate::download::Download;

pub struct DownloadedFile {
    pub file: File,
    pub download: Download,
    pub sha_256: Sha256String,
    pub last_modified: Option<Date>,
}

impl DownloadedFile {
    pub fn architecture(&self) -> Option<Architecture> {
        self.download.architecture()
    }
}
