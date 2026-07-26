use color_eyre::eyre::Report;
use napi::Status;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct InvalidArgument(pub String);

impl From<InvalidArgument> for napi::Error {
    fn from(error: InvalidArgument) -> Self {
        Self::new(Status::InvalidArg, error.0)
    }
}

/// Preserve the complete source chain when an internal failure crosses the N-API boundary.
pub fn to_napi_error(error: Report) -> napi::Error {
    let status = if error.is::<InvalidArgument>() {
        Status::InvalidArg
    } else {
        Status::GenericFailure
    };
    napi::Error::new(status, format!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use color_eyre::eyre::eyre;
    use napi::Status;

    use super::{InvalidArgument, to_napi_error};

    #[test]
    fn failure_messages_include_the_source_error() {
        let error = to_napi_error(
            eyre!("https://example.com/installer.exe: HTTP status code 404 Not Found")
                .wrap_err("Failed to download installer"),
        );

        assert_eq!(
            error.reason,
            "Failed to download installer: https://example.com/installer.exe: HTTP status code 404 Not Found"
        );
        assert_eq!(error.status, Status::GenericFailure);
    }

    #[test]
    fn validation_errors_keep_invalid_argument_status() {
        let error: napi::Error = InvalidArgument("version must not be empty".into()).into();

        assert_eq!(error.status, Status::InvalidArg);
        assert_eq!(error.reason, "version must not be empty");
    }

    #[test]
    fn failure_accepts_standard_errors() {
        let error = to_napi_error(std::io::Error::other("download interrupted").into());

        assert_eq!(error.status, Status::GenericFailure);
        assert_eq!(error.reason, "download interrupted");
    }

    #[test]
    fn contextual_validation_errors_keep_invalid_argument_status() {
        let error = to_napi_error(
            eyre!(InvalidArgument("invalid version".into())).wrap_err("Invalid request"),
        );

        assert_eq!(error.status, Status::InvalidArg);
        assert_eq!(error.reason, "Invalid request: invalid version");
    }
}
