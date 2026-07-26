use reqwest::header::{AUTHORIZATION, DNT, HeaderMap, HeaderValue, USER_AGENT};
use secrecy::{ExposeSecret, SecretString};

const MICROSOFT_DELIVERY_OPTIMIZATION: HeaderValue =
    HeaderValue::from_static("Microsoft-Delivery-Optimization/10.1");
const SEC_GPC: &str = "Sec-GPC";

pub fn default_headers(github_token: Option<&SecretString>) -> HeaderMap {
    let mut default_headers = HeaderMap::new();
    default_headers.insert(USER_AGENT, MICROSOFT_DELIVERY_OPTIMIZATION);
    default_headers.insert(DNT, HeaderValue::from(1));
    default_headers.insert(SEC_GPC, HeaderValue::from(1));
    if let Some(token) = github_token
        && let Ok(mut bearer_auth) =
            HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
    {
        bearer_auth.set_sensitive(true);
        default_headers.insert(AUTHORIZATION, bearer_auth);
    }
    default_headers
}
