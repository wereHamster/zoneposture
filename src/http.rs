use std::error::Error;
use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderMap};
use reqwest::{Client, ClientBuilder, redirect};

pub const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct Clients {
    /// Follows up to 10 redirects, all of which must stay on HTTPS.
    pub https: Client,
    /// Does not follow redirects.
    pub no_redirect: Client,
}

impl Clients {
    pub fn new() -> reqwest::Result<Clients> {
        let https = builder()
            .redirect(redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    attempt.error("redirect to a non-HTTPS URL")
                } else if attempt.previous().len() >= 10 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()?;
        let no_redirect = builder().redirect(redirect::Policy::none()).build()?;
        Ok(Clients { https, no_redirect })
    }
}

fn builder() -> ClientBuilder {
    Client::builder()
        .user_agent(concat!("zoneposture/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
}

#[derive(Debug)]
pub struct Response {
    /// The URL after following redirects.
    pub final_url: String,
    pub status: u16,
    pub headers: HeaderMap,
    /// Empty unless the body was requested and the status is 200.
    pub body: Vec<u8>,
    /// Whether the body exceeded [`MAX_BODY_BYTES`] and was cut off.
    pub truncated: bool,
}

impl Response {
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
    }

    /// The media type of the Content-Type header, lowercase and without
    /// parameters.
    pub fn media_type(&self) -> Option<String> {
        self.content_type()
            .and_then(|value| value.split(';').next())
            .map(|mime| mime.trim().to_ascii_lowercase())
    }
}

pub async fn fetch(client: &Client, url: &str, read_body: bool) -> Result<Response, String> {
    let mut response = client.get(url).send().await.map_err(error_chain)?;
    let final_url = response.url().to_string();
    let status = response.status().as_u16();
    let headers = response.headers().clone();

    let mut body = Vec::new();
    let mut truncated = false;
    if read_body && status == 200 {
        while let Some(chunk) = response.chunk().await.map_err(error_chain)? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY_BYTES {
                truncated = true;
                break;
            }
        }
    }

    Ok(Response {
        final_url,
        status,
        headers,
        body,
        truncated,
    })
}

/// Formats the causes of a request error. reqwest's own message only repeats
/// the URL, so it is used only when there is no underlying cause.
fn error_chain(err: reqwest::Error) -> String {
    let mut causes = Vec::new();
    let mut source = err.source();
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    if causes.is_empty() {
        err.to_string()
    } else {
        causes.join(": ")
    }
}

#[cfg(test)]
pub(crate) fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    Response {
        final_url: "https://example.com/".to_string(),
        status,
        headers: map,
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}
