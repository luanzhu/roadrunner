#![deny(missing_docs)]

//! # Roadrunner (RR)
//!
//! Roadrunner is a rust rest client based on [hyper project](https://github.com/hyperium/hyper) to
//! provide an user friendly interface for use.
//!
//! The API interface is partially inspired by [unirest java library](http://unirest.io/java.html).
//!
//! # Example
//! ```
//! #[macro_use] extern crate serde_derive;
//! extern crate tokio_core;
//!
//! extern crate serde_json;
//! extern crate hyper;
//! extern crate roadrunner;
//!
//! // need both RestClient and RestClientMethods
//! use roadrunner::RestClient;
//! use roadrunner::RestClientMethods;
//!
//! use hyper::StatusCode;
//! use serde_json::Value;
//!
//! #[derive(Serialize, Deserialize, Debug, PartialEq)]
//! struct Address {
//!   street: String,
//!   city: String,
//! }
//!
//! fn main () {
//!     let mut core = tokio_core::reactor::Core::new().unwrap();
//! 
//!     let original_typed = Address {
//!         street: "135 College View Ave.".to_owned(),
//!         city: "San Francisco".to_owned(),
//!     };
//!
//!     // Hit the local httpbin container in docker.
//!     // Please see a similar example in repo readme
//!     // (https://github.com/luanzhu/roadrunner) if you would like to try
//!     // this example.
//!     let response = RestClient::post("http://localhost:8000/post")
//!         .cookie("food", "bar")
//!         .authorization_bearer("QWxhZGRpbjpvcGVuIHNlc2FtZQ".to_string())
//!         .json_body_typed(&original_typed)
//!         .execute_on(&mut core)
//!         .unwrap();
//!
//!     println!("{:?}", response);
//!
//!     assert_eq!(*response.status(), StatusCode::Ok);
//!
//!     let json_value = response.content().as_value().unwrap();
//!     assert_eq!(Value::String("application/json".to_owned()),
//!                 json_value["headers"]["Content-Type"]);
//!
//!     let data_str = json_value["data"].as_str().unwrap();
//!
//!     println!("data_str : {:?}", data_str);
//!
//!     let response_typed: Address = serde_json::from_str(data_str).unwrap();
//!     assert_eq!(original_typed, response_typed);
//! }
//! ```
//!
//! # Usage
//!
//! ## High level
//!
//! High level API access is provided through **RestClient** and methods available in trait
//! **RestClientMethods**.
//!
//! Please refer to tests in the tests folder for more example.
//!
//! ## Low level
//!
//! For more control of request settings, use **request_for_response**.  The high level RestClient is
//! a thin layer on top of this function.
//!
//! # Supported Methods
//!
//! * GET
//! * POST
//! * PUT
//! * PATCH
//! * DELETE
//! * OPTIONS
//!

#[macro_use]
extern crate log;

extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate native_tls;
extern crate tokio_core;
extern crate serde_json;
extern crate tokio_service;
extern crate mime;
extern crate encoding;
extern crate flate2;
extern crate serde;
extern crate url;

use std::error;
use std::fmt;
use std::borrow::Cow;
use std::io::Read;
use std::convert::From;
use hyper::Client;
use hyper::StatusCode;
use hyper::header::{Headers, AcceptEncoding, ContentEncoding, ContentType, Charset, AcceptCharset,
                    qitem, Encoding as HyperEncoding, UserAgent, Cookie, QualityItem};
use mime::Mime;
use hyper::HttpVersion;
use futures::Future;
use futures::stream::Stream;
use futures::future;
use hyper::client::Request;
use hyper_tls::HttpsConnector;
use serde_json::Value;
use serde::de::DeserializeOwned;
use tokio_core::reactor::Core;

use flate2::read::{GzDecoder, ZlibDecoder};

const DNS_THREAD_COUNT: usize = 4;

/// Default user agent will be sent with request if user agent is not specified.
pub const DEFAULT_USER_AGENT: &str = "Roadrunner (a rust rest client) v0.1.0";
/// The user agent is used when `user_agent_chrome` is called.
pub const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36";
/// The user agent is used when `user_agent_firefox` is called.`
pub const FIREFOX_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:53.0) \
Gecko/20100101 Firefox/53.0";

/// RestClient is used to configure request.
///
/// Together with the trait `RestClientMethods`, it provides a high level API
/// interface that is somewhat similar to [unirest java library](http://unirest.io/java.html).
pub struct RestClient {
    url: url::Url,
    request: Request,
    cookie: Cookie,

    form_fields: Option<url::form_urlencoded::Serializer<String>>,
    json_body_str: Option<String>,
}

impl RestClient {
    /// Initialize a RestClient for a GET request.
    pub fn get(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Get)
    }
    /// Initialize a RestClient for a DELETE request.
    pub fn delete(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Delete)
    }
    /// Initialize a RestClient for a POST request.
    pub fn post(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Post)
    }
    /// Initialize a RestClient for a PUT request.
    pub fn put(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Put)
    }
    /// Initialize a RestClient for a PATCH request.
    pub fn patch(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Patch)
    }
    /// Initialize a RestClient for a OPTIONS request.
    pub fn options(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Options)
    }

    fn new(url: &str, method: hyper::Method) -> Result<Self, Error> {
        let uri = try!(url.parse::<hyper::Uri>());

        let parsed_url = try!(url::Url::parse(url));

        let client = RestClient {
            url: parsed_url,
            request: Request::new(method, uri),
            cookie: Cookie::new(),

            form_fields: None,
            json_body_str: None,
        };

        Ok(client)
    }

    fn cookie<K, V>(mut self, name: K, value: V) -> Self
        where K: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>> {
        self.cookie.append(name, value);

        self
    }

    fn authorization_basic(mut self, username: String, password: String) -> Self {
        self.request.headers_mut().set(
          hyper::header::Authorization(
              hyper::header::Basic {
                  username: username,
                  password: Some(password),
              }
          )
        );

        self
    }

    fn authorization_bearer(mut self, token: String) -> Self {
        self.request.headers_mut().set(
            hyper::header::Authorization(
                hyper::header::Bearer {
                    token: token,
                }
            )
        );

        self
    }

    fn authorization_string(mut self, custom: String) -> Self {
        self.request.headers_mut().set(
            hyper::header::Authorization(custom)
        );

        self
    }

    fn accept(mut self, media_type: QualityItem<Mime>) -> Self {
        self.request.headers_mut().set(hyper::header::Accept(vec![media_type]));

        self
    }

    fn header_set_raw<K>(mut self, name: K, values: Vec<String>) -> Self
        where K: Into<Cow<'static, str>> {

        let mut value_vector: Vec<Vec<u8>> = Vec::new();

        for v in values.into_iter() {
            value_vector.push(v.into_bytes());
        }

        self.request.headers_mut().set_raw(name, value_vector);

        self
    }

    fn header_append_raw<K>(mut self, name: K, value: String) -> Self
        where K: Into<Cow<'static, str>> {

        self.request.headers_mut().append_raw(name, value.into_bytes());

        self
    }

    fn query_param(mut self, name: &str, value: &str) -> Self {
        self.url.query_pairs_mut()
            .append_pair(name, value);

        self
    }

    fn form_field(mut self, name: &str, value: &str) -> Self {
        let mut temp_form_fields = match self.form_fields {
            Some(ffs) => ffs,
            None => url::form_urlencoded::Serializer::new(String::new()),
        };

        temp_form_fields.append_pair(name, value);

        self.form_fields = Some(temp_form_fields);

        self
    }

    fn json_body_str(mut self, json_string: String) -> Self {
        self.json_body_str = Some(json_string);

        self
    }

    fn user_agent<K>(mut self, agent: K) -> Self
        where K: Into<Cow<'static, str>> {

        self.request.headers_mut().set(hyper::header::UserAgent::new(agent));

        self
    }

    fn execute_on(mut self, core: &mut Core) -> Result<Response, Error> {
        self.request.headers_mut().set(self.cookie);

        match self.request.headers().get::<hyper::header::Accept>() {
            Some(_) => {},
            None => {
                self.request.headers_mut().set(hyper::header::Accept::json());
            }
        }

        // for url query parameters
        let updated_url_str = self.url.as_str();
        let updated_uri = try!(updated_url_str.parse::<hyper::Uri>());
        self.request.set_uri(updated_uri);

        // TODO: give error when both form fields and json body are set

        // for form fields
        match self.form_fields {
            Some(ref mut ffs) => {
                let encoded = ffs.finish();

                self.request.set_body(encoded);
                self.request.headers_mut().set(ContentType::form_url_encoded());

                debug!("Content-Type is set to application/x-www-form-urlencoded");
            },
            None => {}
        };

        match self.json_body_str {
            Some(body_str) => {
                self.request.set_body(body_str);
                self.request.headers_mut().set(ContentType::json());

                debug!("Content-Type is set to application/json");
            },
            None => {},
        }

        match self.request.headers().get::<hyper::header::UserAgent>() {
            Some(_) => {},
            None => {
                debug!("Setting user agent to default for {}", self.request.uri());
                self.request
                    .headers_mut()
                    .set(UserAgent::new(DEFAULT_USER_AGENT));
            },
        }

        self.request
            .headers_mut()
            .set(AcceptCharset(vec![qitem(Charset::Ext("utf-8".to_string()))]));

        self.request
            .headers_mut()
            .set(AcceptEncoding(vec![qitem(HyperEncoding::Gzip),
                                     qitem(HyperEncoding::Deflate),
                                     qitem(HyperEncoding::Chunked),
                                     qitem(HyperEncoding::Identity)]));

        request_for_response(self.request, core)
    }
}

/// Provides a high level API that one can use to configure and execute a request.
pub trait RestClientMethods {
    /// Set cookie for request, can be called multiple times to set multiple cookies.
    fn cookie<K, V>(self, name: K, value: V) -> Self
        where K: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>>;

    /// Set username and password for basic authentication header.
    fn authorization_basic(self, username: String, password: String) -> Self;
    /// Set oauth token for oauth authentication.
    fn authorization_bearer(self, token: String) -> Self;
    /// Set a custom authentication header.
    fn authorization_string(self, custom: String) -> Self;

    /// Set Accept header for the request. If none is specified, the
    /// default *application/json* will be used.
    fn accept(self, media_type: QualityItem<Mime>) -> Self;

    /// Set a header with a raw string, existing value of the
    /// same header will be overwritten.
    fn header_set_raw<K>(self, name: K, values: Vec<String>) -> Self
        where K: Into<Cow<'static, str>>;
    /// Append a header with a raw string, existing value of the
    /// same header will NOT be overwritten.
    fn header_append_raw<K>(self, name: K, value: String) -> Self
        where K: Into<Cow<'static, str>>;

    /// Append url query parameters.
    fn query_param(self, name: &str, value: &str) -> Self;

    /// Set form fields for the request. This method can be called
    /// multiple times.  All fields will be encoded and send as
    /// request body.
    ///
    /// Note: Content-Type will be set to *application/x-www-form-urlencoded*.
    fn form_field(self, name: &str, value: &str) -> Self;

    /// Set request body as a json string.
    ///
    /// Note: Content-Type will be set to *application/json*.
    fn json_body_str(self, json_string: String) -> Self;
    /// Parameter typed_value will be serialized into a json string and
    /// sent as the request body.
    ///
    /// Note: Content-Type will be set to *application/json*.
    fn json_body_typed<T>(self, typed_value: &T) -> Self
        where T: serde::Serialize;

    /// Set the user agent header for request.  If none is specified,
    /// the default string `DEFAULT_USER_AGENT` will be used.
    fn user_agent<K>(self, agent: K) -> Self
        where K: Into<Cow<'static, str>>;
    /// Set the user agent as firefox.  This may be needed when a server
    /// only accepts requests from well-known user agents.
    fn user_agent_firefox(self) -> Self;
    /// Set the user agent as chrome.
    fn user_agent_chrome(self) -> Self;

    /// Finish setting up the request, and kick off request execution
    /// on a `tokio_core::reactor::Core`.
    fn execute_on(self, core: &mut Core) -> Result<Response, Error>;
}

impl RestClientMethods for Result<RestClient, Error> {
    fn cookie<K, V>(self, name: K, value: V) -> Self
        where K: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>> {

        self.map(|client| { client.cookie(name, value) })
    }

    fn authorization_basic(self, username: String, password: String) -> Self {
        self.map(|client| { client.authorization_basic(username, password) })
    }

    fn authorization_bearer(self, token: String) -> Self {
        self.map(|client| { client.authorization_bearer(token) })
    }

    fn authorization_string(self, custom: String) -> Self {
        self.map(|client| { client.authorization_string(custom) })
    }

    fn accept(self, media_type: QualityItem<Mime>) -> Self {
        self.map(|client| { client.accept(media_type) })
    }

    fn header_set_raw<K>(self, name: K, values: Vec<String>) -> Self
        where K: Into<Cow<'static, str>> {

        self.map(|client| { client.header_set_raw(name, values) })
    }

    fn header_append_raw<K>(self, name: K, value: String) -> Self
        where K: Into<Cow<'static, str>> {

        self.map(|client| { client.header_append_raw(name, value) })
    }

    fn query_param(self, name: &str, value: &str) -> Self {
        self.map(|client| { client.query_param(name, value) })
    }

    fn form_field(self, name: &str, value: &str) -> Self {
        self.map(|client| { client.form_field(name, value) })
    }

    fn json_body_str(self, json_string: String) -> Self {
        self.map(|client| { client.json_body_str(json_string) })
    }

    fn json_body_typed<T>(self, typed_value: &T) -> Self
        where T: serde::Serialize {

        serde_json::to_string(typed_value)
            .map_err(Error::JsonError)
            .and_then(|s| { self.json_body_str(s) })
    }

    fn user_agent<K>(self, agent: K) -> Self
        where K: Into<Cow<'static, str>> {

        self.map(|client| { client.user_agent(agent) })
    }

    fn user_agent_firefox(self) -> Self {
        self.user_agent(FIREFOX_USER_AGENT)
    }

    fn user_agent_chrome(self) -> Self {
        self.user_agent(CHROME_USER_AGENT)
    }

    fn execute_on(self, core: &mut Core) -> Result<Response, Error> {
        self.and_then(|client| { client.execute_on(core) })
    }
}

/// Holds the body content of a response.
#[derive(Debug)]
pub struct Content {
    content_string: String,
}

impl Content {
    fn new(s: String) -> Self {
        Content { content_string: s }
    }

    /// Get the raw body content as a `&str`.
    pub fn as_ref_string(&self) -> &str {
        &self.content_string
    }

    /// Get the body content as a `serde_json::value::Value`.
    pub fn as_value(&self) -> Result<Value, Error> {
        serde_json::from_str(&self.content_string)
            .map_err(::std::convert::From::from)
    }

    /// Get the body content as a strongly typed struct.
    ///
    /// The struct has to implement Serde's `Deserialize` trait.
    pub fn as_typed<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_str(&self.content_string)
            .map_err(::std::convert::From::from)
    }
}

/// Holds response received from server after a request is executed.
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    version: HttpVersion,
    content: Content,
}

impl Response {
    /// Get the response status code.
    pub fn status(&self) -> &StatusCode {
        &self.status
    }
    /// Get the response body content.
    pub fn content(&self) -> &Content {
        &self.content
    }
    /// Get response headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}

/// The error that can happen during a request.
#[derive(Debug)]
pub enum Error {
    /// Indicate an url parsing error.
    UrlParse(url::ParseError),
    /// Also indicate an url parsing error.
    UriParse(hyper::error::UriError),
    /// Error reported by hyper.
    Hyper(hyper::Error),
    /// Response content cannot be decoded successfully.
    CharsetDecode,
    /// IO error.
    Io(std::io::Error),
    /// Error reported by serde_json.
    JsonError(serde_json::Error),
    /// native_tls error
    NativeTlsError(native_tls::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UrlParse(ref err) => write!(f, "Url parse error: {}", err),
            Error::UriParse(ref err) => write!(f, "Uri parse error: {}", err),
            Error::Hyper(ref err) => write!(f, "Hyper error: {}", err),
            Error::CharsetDecode => write!(f, "Character set decode error"),
            Error::Io(ref err) => write!(f, "Decompress IO error: {}", err),
            Error::JsonError(ref err) => write!(f, "Json error: {}", err),
            Error::NativeTlsError(ref err) => write!(f, "native-tls error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UrlParse(ref err) => err.description(),
            Error::UriParse(ref err) => err.description(),
            Error::Hyper(ref err) => err.description(),
            Error::CharsetDecode => "Character set decode error",
            Error::Io(ref err) => err.description(),
            Error::JsonError(ref err) => err.description(),
            Error::NativeTlsError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::UrlParse(ref err) => Some(err),
            Error::UriParse(ref err) => Some(err),
            Error::Hyper(ref err) => Some(err),
            Error::CharsetDecode => None,
            Error::Io(ref err) => Some(err),
            Error::JsonError(ref err) => Some(err),
            Error::NativeTlsError(ref err) => Some(err),
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParse(err)
    }
}

impl From<hyper::error::UriError> for Error {
    fn from(err: hyper::error::UriError) -> Error {
        Error::UriParse(err)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Error {
        Error::Hyper(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::JsonError(err)
    }
}

impl From<native_tls::Error> for Error {
    fn from(err: native_tls::Error) -> Error {
        Error::NativeTlsError(err)
    }
}

/// This function provides a low level API interface that one can
/// use if the high level API is not sufficient.
///
/// `RestClient` and `RestClientMethods` ony provide limited methods to
/// customize a request. This function, on the other hand, gives users
/// the complete control of how a request is configured.
pub fn request_for_response(request: hyper::client::Request, core: &mut Core) -> Result<Response, Error> {
    let handle = core.handle();

    // no need to have a seperate http connector because the https connector
    // can do both
    let connector = HttpsConnector::new(DNS_THREAD_COUNT, &handle)?;

    let step1 = Client::configure()
                .connector(connector)
                .build(&handle)
                .request(request);

    let work = step1
        .map_err(Error::Hyper)
        .and_then(|res| {
            let status = res.status();
            let headers = res.headers().clone();
            let version = res.version();

            let content_encoding = headers.get::<ContentEncoding>().map(|enc| enc.clone());

            let content_type = headers.get::<ContentType>().map(|c| c.clone());

            res.body()
                .fold(Vec::new(), |mut v, chunk| {
                    v.extend(&chunk[..]);

                    future::ok::<_, hyper::Error>(v)
                })
                .map_err(::std::convert::From::from)
                .and_then(move |chunks| match decode_input_based_on_content_type(chunks,
                                                                                 content_encoding) {
                                Ok(decoded) => future::ok(decoded),
                                Err(err) => future::err(err),
                          })
                .and_then(move |chunks| match decode_to_string(chunks, content_type) {
                              Ok(s) => {
                                let r = Response {
                                    status: status,
                                    headers: headers,
                                    version: version,
                                    content: Content::new(s),
                                };
                                future::ok::<_, Error>(r)
                            }
                              Err(err) => future::err(err),
                })
        });

    core.run(work).map_err(::std::convert::From::from)
}

fn decode_input_based_on_content_type(input: Vec<u8>,
                                      content_encoding: Option<ContentEncoding>)
                                      -> Result<Vec<u8>, Error> {
    let mut input = input;

    match content_encoding {
        Some(encodings) => {
            for encoding in encodings.iter().rev() {
                match *encoding {
                    HyperEncoding::Gzip => {
                        input = try!(decompress_gzip(input.as_slice()));
                    }

                    HyperEncoding::Deflate => {
                        input = try!(decompress_deflate(input.as_slice()));
                    }

                    _ => {}
                }
            }
        }
        None => {}
    };

    Ok(input)
}

fn decompress_gzip(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body_buffer: Vec<u8> = Vec::new();

    {
        let mut decompressor = try!(GzDecoder::new(input));

        try!(decompressor.read_to_end(&mut body_buffer));

    }

    Ok(body_buffer)
}

fn decompress_deflate(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body_buffer: Vec<u8> = Vec::new();

    {
        let mut decompressor = ZlibDecoder::new(input);

        try!(decompressor.read_to_end(&mut body_buffer));
    }

    Ok(body_buffer)
}

fn decode_to_string(chunks: Vec<u8>, content_type: Option<ContentType>) -> Result<String, Error> {
    content_type.as_ref()
        .and_then(|content_type_header| 
            content_type_header.get_param(hyper::mime::CHARSET))
        .and_then(|charset| {
            encoding::label::encoding_from_whatwg_label(charset.as_ref()) })
        .unwrap_or(encoding::all::UTF_8)
        .decode(&chunks, encoding::DecoderTrap::Strict)
        .map_err(|_| Error::CharsetDecode)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::mime;

    #[test]
    fn decode_to_string_test_utf8() {
        assert_eq!("Hello".to_string(),
                   decode_to_string(vec![72, 101, 108, 108, 111], None).unwrap());
        assert_eq!("Hello".to_string(),
                   decode_to_string(vec![72, 101, 108, 108, 111], Some(ContentType::json()))
                       .unwrap());
        assert_eq!("Hello".to_string(),
                   decode_to_string(vec![72, 101, 108, 108, 111],
                                    Some(ContentType(mime::TEXT_PLAIN_UTF_8)))
                       .unwrap());
    }

    #[test]
    fn decode_to_string_test_iso_8859_1() {
        assert_eq!("caf\u{e9}".to_string(), decode_to_string(vec![99,97,102,233], 
            Some(ContentType("text/html; charset=iso-8859-1".parse::<mime::Mime>().unwrap())))
            .unwrap());
    }

    #[test]
    #[should_panic]
    fn decode_to_string_test_iso_8859_1_with_utf8_decode() {
        assert!("caf\u{e9}".to_string() !=
                decode_to_string(vec![99, 97, 102, 233],
                                 Some(ContentType("txt/html; charset=utf-8".parse::<mime::Mime>().unwrap())))
                        .unwrap());
    }

    #[test]
    #[should_panic]
    fn decode_to_string_test_iso_8859_1_with_default_utf8_decode() {
        assert!("caf\u{e9}".to_string() != decode_to_string(vec![99, 97, 102, 233], None).unwrap());
    }
}
