use color_eyre::eyre::Report;
use napi::{Error, Status};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnthelionError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0:#}")]
    Failure(Report),
}

pub type AnthelionResult<T> = Result<T, AnthelionError>;

impl AnthelionError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidArgument(reason.into())
    }

    pub fn failure(report: Report) -> Self {
        Self::Failure(report)
    }
}

impl From<AnthelionError> for Error {
    fn from(error: AnthelionError) -> Self {
        let status = match error {
            AnthelionError::InvalidArgument(_) => Status::InvalidArg,
            AnthelionError::Failure(_) => Status::GenericFailure,
        };
        Self::new(status, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use color_eyre::eyre::eyre;

    use super::AnthelionError;

    #[test]
    fn failure_messages_include_the_source_error() {
        let error = AnthelionError::failure(
            eyre!("https://example.com/installer.exe: HTTP status code 404 Not Found")
                .wrap_err("Failed to download installer"),
        );

        assert_eq!(
            error.to_string(),
            "Failed to download installer: https://example.com/installer.exe: HTTP status code 404 Not Found"
        );
    }
}
