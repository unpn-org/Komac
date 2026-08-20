use std::{any::Any, error::Error as _, future::Future, pin::Pin, time::Duration};

use cynic::{GraphQlError, GraphQlResponse, Operation, http::CynicReqwestError};
use reqwest::{
    Client, Response, StatusCode,
    header::{HeaderMap, RETRY_AFTER},
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{
    Jitter, RetryTransientMiddleware, Retryable, RetryableStrategy, default_on_request_failure,
    default_on_request_success, policies::ExponentialBackoff,
};
use serde::{Serialize, de::DeserializeOwned};

use super::{GitHubError, client::GitHub, graphql::GRAPHQL_URL};

const MAX_GITHUB_REQUEST_RETRIES: u32 = 3;
const MIN_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(30);

type ErasedGraphQlResponse = Box<dyn Any + Send>;
type DeserializeGraphQlResponseFuture = Pin<
    Box<dyn Future<Output = Result<(ErasedGraphQlResponse, bool), GitHubError>> + Send + 'static>,
>;
type DeserializeGraphQlResponse =
    fn(reqwest_middleware::Result<Response>) -> DeserializeGraphQlResponseFuture;

pub(crate) fn client(client: Client) -> ClientWithMiddleware {
    let retry_policy = ExponentialBackoff::builder()
        .retry_bounds(MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL)
        .jitter(Jitter::Bounded)
        .build_with_max_retries(MAX_GITHUB_REQUEST_RETRIES);

    ClientBuilder::new(client)
        .with(RetryTransientMiddleware::new_with_policy_and_strategy(
            retry_policy,
            GitHubRetryableStrategy,
        ))
        .build()
}

pub(crate) fn is_connect_error(error: &reqwest_middleware::Error) -> bool {
    if error.is_connect() {
        return true;
    }

    let mut source = error.source();
    while let Some(error) = source {
        if error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_connect)
        {
            return true;
        }

        source = error.source();
    }

    false
}

impl GitHub {
    pub(super) async fn run_graphql_with_retry<ResponseData, Vars>(
        &self,
        operation: &Operation<ResponseData, Vars>,
    ) -> Result<GraphQlResponse<ResponseData>, GitHubError>
    where
        ResponseData: DeserializeOwned + Send + 'static,
        Vars: Serialize,
    {
        let request = self
            .0
            .post(GRAPHQL_URL)
            .json(operation)
            .build()
            .map_err(reqwest_middleware::Error::from)?;
        let response = run_graphql_request_with_retry(
            &self.0,
            &request,
            erase_graphql_response::<ResponseData>,
        )
        .await?;

        Ok(*response
            .downcast::<GraphQlResponse<ResponseData>>()
            .expect("GraphQL response type must match its deserializer"))
    }
}

#[inline(never)]
async fn run_graphql_request_with_retry(
    client: &ClientWithMiddleware,
    request: &reqwest::Request,
    deserialize: DeserializeGraphQlResponse,
) -> Result<ErasedGraphQlResponse, GitHubError> {
    for retry in 0..=MAX_GITHUB_REQUEST_RETRIES {
        let request = request
            .try_clone()
            .expect("GraphQL requests always have a cloneable JSON body");
        let (response, retryable) = deserialize(client.execute(request).await).await?;

        if retry == MAX_GITHUB_REQUEST_RETRIES || !retryable {
            return Ok(response);
        }

        let delay = graphql_retry_delay(retry);
        tracing::info!(
            retry = retry + 1,
            max_retries = MAX_GITHUB_REQUEST_RETRIES,
            delay_secs = delay.as_secs(),
            "Retrying GitHub GraphQL request after transient error"
        );
        tokio::time::sleep(delay).await;
    }

    unreachable!("GraphQL retry loop must return before exceeding max retries");
}

struct GitHubRetryableStrategy;

impl RetryableStrategy for GitHubRetryableStrategy {
    fn handle(&self, result: &Result<Response, reqwest_middleware::Error>) -> Option<Retryable> {
        match result {
            Ok(response) if is_retryable_response(response) => Some(Retryable::Transient),
            Ok(response) => default_on_request_success(response),
            Err(error) => default_on_request_failure(error),
        }
    }
}

async fn deserialize_graphql_response<ResponseData>(
    response: reqwest_middleware::Result<Response>,
) -> Result<GraphQlResponse<ResponseData>, GitHubError>
where
    ResponseData: DeserializeOwned,
{
    let response = response?;

    let status = response.status();
    if status.is_success() {
        Ok(response
            .json()
            .await
            .map_err(CynicReqwestError::ReqwestError)?)
    } else {
        let text = response.text().await?;

        if let Ok(response) = serde_json::from_slice(text.as_bytes()) {
            Ok(response)
        } else {
            Err(CynicReqwestError::ErrorResponse(status, text).into())
        }
    }
}

fn erase_graphql_response<ResponseData>(
    response: reqwest_middleware::Result<Response>,
) -> DeserializeGraphQlResponseFuture
where
    ResponseData: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let response = deserialize_graphql_response::<ResponseData>(response).await?;
        let retryable = is_retryable_graphql_response(&response);
        Ok((Box::new(response) as ErasedGraphQlResponse, retryable))
    })
}

fn is_retryable_response(response: &Response) -> bool {
    is_retryable_status(response.status(), response.headers())
}

fn is_retryable_graphql_response<ResponseData>(response: &GraphQlResponse<ResponseData>) -> bool {
    response
        .errors
        .as_ref()
        .is_some_and(|errors| errors.iter().any(is_retryable_graphql_error))
}

fn is_retryable_graphql_error(error: &GraphQlError) -> bool {
    error
        .message
        .starts_with("Something went wrong while executing your query")
}

fn is_retryable_status(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
        || (status == StatusCode::FORBIDDEN && headers.contains_key(RETRY_AFTER))
}

fn graphql_retry_delay(retry: u32) -> Duration {
    MIN_RETRY_INTERVAL
        .saturating_mul(2_u32.saturating_pow(retry))
        .min(MAX_RETRY_INTERVAL)
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    #[test]
    fn retryable_status_codes() {
        let headers = HeaderMap::new();

        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT, &headers));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS, &headers));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY, &headers));
        assert!(is_retryable_status(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers
        ));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT, &headers));

        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED, &headers));
        assert!(!is_retryable_status(StatusCode::FORBIDDEN, &headers));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND, &headers));
    }

    #[test]
    fn forbidden_with_retry_after_is_retryable() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("1"));

        assert!(is_retryable_status(StatusCode::FORBIDDEN, &headers));
    }

    #[test]
    fn github_internal_graphql_error_is_retryable() {
        let response = GraphQlResponse::<()> {
            data: None,
            errors: Some(vec![GraphQlError::new(
                "Something went wrong while executing your query on 2026-05-30T14:08:34Z. Please include `1601:106F03:698CB68:1920E102:6A1AEF61` when reporting this issue.".to_owned(),
                None,
                None,
                None,
            )]),
        };

        assert!(is_retryable_graphql_response(&response));
    }

    #[test]
    fn validation_graphql_error_is_not_retryable() {
        let response = GraphQlResponse::<()> {
            data: None,
            errors: Some(vec![GraphQlError::new(
                "Could not resolve to a Repository with the name 'owner/repo'.".to_owned(),
                None,
                None,
                None,
            )]),
        };

        assert!(!is_retryable_graphql_response(&response));
    }

    #[test]
    fn graphql_retry_delay_uses_exponential_backoff_bounds() {
        assert_eq!(graphql_retry_delay(0), Duration::from_secs(1));
        assert_eq!(graphql_retry_delay(1), Duration::from_secs(2));
        assert_eq!(graphql_retry_delay(2), Duration::from_secs(4));
        assert_eq!(graphql_retry_delay(u32::MAX), MAX_RETRY_INTERVAL);
    }
}
