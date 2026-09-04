use cynic::impl_scalar;
use jiff::Timestamp;
use url::Url;

use super::types::GitRefName;

#[cynic::schema("github")]
pub mod github_schema {}

impl_scalar!(Url, github_schema::URI);
impl_scalar!(Timestamp, github_schema::DateTime);
impl_scalar!(GitRefName, github_schema::GitRefname);
