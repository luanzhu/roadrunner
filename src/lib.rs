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
//! use hyper::status::StatusCode;
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
//!         city: "Greenville".to_owned(),
//!     };
//!
//!     let response = RestClient::post("http://mockbin.com/request")
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
//!                 json_value["headers"]["content-type"]);
//!
//!     let data_str = json_value["postData"]["text"].as_str().unwrap();
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
use log::LogLevel;
use hyper::Client;
use hyper::status::StatusCode;
use hyper::header::{Headers, AcceptEncoding, ContentEncoding, ContentType, Charset, AcceptCharset,
                    qitem, q, Encoding as HyperEncoding, UserAgent, Cookie, QualityItem};
use mime::Mime;
use hyper::HttpVersion;
use futures::Future;
use futures::stream::Stream;
use futures::future;
use hyper::client::{Connect, Request};
use hyper_tls::HttpsConnector;
use serde_json::Value;
use serde::de::DeserializeOwned;
use tokio_core::reactor::{Handle, Core};

use flate2::read::{GzDecoder, ZlibDecoder};
use encoding::Encoding;

const DNS_THREAD_COUNT: usize = 4;
const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36";
const FIREFOX_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:53.0) \
Gecko/20100101 Firefox/53.0";

pub struct RestClient {
    url: url::Url,
    request: Request,
    cookie: Cookie,

    form_fields: Option<url::form_urlencoded::Serializer<String>>,
    json_body_str: Option<String>,
}

impl RestClient {
    pub fn get(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Get)
    }

    pub fn delete(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Delete)
    }

    pub fn post(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Post)
    }

    pub fn put(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Put)
    }

    pub fn patch(url: &str) -> Result<Self, Error> {
        RestClient::new(url, hyper::Method::Patch)
    }

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

        request_for_response(self.request, core)
    }
}

pub trait RestClientMethods {
    fn cookie<K, V>(self, name: K, value: V) -> Self
        where K: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>>;

    fn authorization_basic(self, username: String, password: String) -> Self;

    fn authorization_bearer(self, token: String) -> Self;
    fn authorization_string(self, custom: String) -> Self;
    fn accept(self, media_type: QualityItem<Mime>) -> Self;

    fn header_set_raw<K>(self, name: K, values: Vec<String>) -> Self
        where K: Into<Cow<'static, str>>;
    fn header_append_raw<K>(self, name: K, value: String) -> Self
        where K: Into<Cow<'static, str>>;

    fn query_param(self, name: &str, value: &str) -> Self;

    fn form_field(self, name: &str, value: &str) -> Self;
    fn json_body_str(self, json_string: String) -> Self;
    fn json_body_typed<T>(self, typed_value: &T) -> Self
        where T: serde::Serialize;

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

    fn accept(mut self, media_type: QualityItem<Mime>) -> Self {
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

    fn execute_on(self, core: &mut Core) -> Result<Response, Error> {
        self.and_then(|client| { client.execute_on(core) })
    }
}


#[derive(Debug)]
pub struct Content {
    content_string: String,
}

impl Content {
    fn new(s: String) -> Self {
        Content { content_string: s }
    }

    pub fn as_ref_string(&self) -> &str {
        &self.content_string
    }

    pub fn as_value(&self) -> Result<Value, Error> {
        serde_json::from_str(&self.content_string)
            .map_err(::std::convert::From::from)
    }

    pub fn as_typed<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_str(&self.content_string)
            .map_err(::std::convert::From::from)
    }
}

#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    version: HttpVersion,
    content: Content,
}

impl Response {
    pub fn status(&self) -> &StatusCode {
        &self.status
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}

#[derive(Debug)]
pub enum Error {
    UrlParse(url::ParseError),
    UriParse(hyper::error::UriError),
    Hyper(hyper::Error),
    CharsetDecode,
    Io(std::io::Error),
    JsonError(serde_json::Error),
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

pub fn request_for_response(request: hyper::client::Request, core: &mut Core) -> Result<Response, Error> {
    let handle = core.handle();

    let connector = HttpsConnector::new(DNS_THREAD_COUNT, &handle);

    let mut request = request;
    request
        .headers_mut()
        .set(AcceptCharset(vec![qitem(Charset::Ext("utf-8".to_string()))]));

    request
        .headers_mut()
        .set(AcceptEncoding(vec![qitem(HyperEncoding::Gzip),
                                 qitem(HyperEncoding::Deflate),
                                 qitem(HyperEncoding::Chunked),
                                 qitem(HyperEncoding::Identity)]));

    debug!("Setting user agent to default firefox for request {}", request.uri());
    request
        .headers_mut()
        .set(UserAgent::new(FIREFOX_USER_AGENT));

    let request = request;

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
            println!("{:?}", content_type);

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
    let decoder = match content_type {
        Some(content_type_header) => {
            match content_type_header.get_param(hyper::mime::Attr::Charset) {
                Some(charset) => encoding::label::encoding_from_whatwg_label(charset),
                None => None,
            }
        }
        None => None,
    };

    match decoder {
        Some(request_decoder) => {
            request_decoder
                .decode(&chunks, encoding::DecoderTrap::Strict)
                .map_err(|_| Error::CharsetDecode)
        }
        None => {
            encoding::all::UTF_8
                .decode(&chunks, encoding::DecoderTrap::Strict)
                .map_err(|_| Error::CharsetDecode)
        }
    }
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
                                    Some(ContentType(mime::Mime(mime::TopLevel::Text,
                                                                mime::SubLevel::Html,
                                                                vec![(mime::Attr::Charset,
                                                                      mime::Value::Utf8)]))))
                           .unwrap());
    }

    #[test]
    fn decode_to_string_test_iso_8859_1() {
        assert_eq!("caf\u{e9}".to_string(), decode_to_string(vec![99,97,102,233], 
            Some(ContentType(mime::Mime(mime::TopLevel::Text, mime::SubLevel::Html,
                vec![(mime::Attr::Charset, mime::Value::Ext("iso-8859-1".to_string()))])))).unwrap());
    }

    #[test]
    #[should_panic]
    fn decode_to_string_test_iso_8859_1_with_utf8_decode() {
        assert!("caf\u{e9}".to_string() !=
                decode_to_string(vec![99, 97, 102, 233],
                                 Some(ContentType(mime::Mime(mime::TopLevel::Text,
                                                             mime::SubLevel::Html,
                                                             vec![(mime::Attr::Charset,
                                                                   mime::Value::Utf8)]))))
                        .unwrap());
    }

    #[test]
    #[should_panic]
    fn decode_to_string_test_iso_8859_1_with_default_utf8_decode() {
        assert!("caf\u{e9}".to_string() != decode_to_string(vec![99, 97, 102, 233], None).unwrap());
    }
}
