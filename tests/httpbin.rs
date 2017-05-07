

const HTTP_BIN_URL_BASE: &str  = "http://localhost:8000";
const HTTPS_BIN_URL_BASE: &str = "https://localhost:8001";

pub fn to_full_http_url(path: &str) -> String {
    let mut url = String::new();

    url.push_str(HTTP_BIN_URL_BASE);
    url.push_str(path);

    url
}

pub fn to_full_https_url(path: &str) -> String {
    let mut url = String::new();

    url.push_str(HTTPS_BIN_URL_BASE);
    url.push_str(path);

    url
}

