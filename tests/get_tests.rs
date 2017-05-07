extern crate roadrunner;
extern crate tokio_core;
extern crate hyper;
extern crate serde_json;
extern crate base64;
extern crate mime;

extern crate env_logger;

#[macro_use]
extern crate serde_derive;

use roadrunner::RestClient;
use roadrunner::RestClientMethods;
use hyper::status::StatusCode;
use serde_json::Value;

use base64::encode;

mod httpbin;

#[derive(Serialize, Deserialize)]
#[derive(Debug)]
struct GetResponse {
    url: String,
}

fn setup() {
    let _ = env_logger::init();
}

#[test]
fn rest_client_query_param_multi_value_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/get"))
        .query_param("foo", "bar1")
        .query_param("foo", "bar2")
        .header_append_raw("Custom-Header1", "value2".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::Array(vec![Value::String("bar1".to_string()),
                                 Value::String("bar2".to_owned())]), json_value["args"]["foo"]);
}

#[test]
fn rest_client_query_param_append_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/get?foo=bar"))
        .query_param("hello", "world")
        .header_append_raw("Custom-Header1", "value2".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("bar".to_string()), json_value["args"]["foo"]);
    assert_eq!(Value::String("world".to_string()), json_value["args"]["hello"]);
}

#[test]
fn rest_client_query_param_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/get"))
        .query_param("foo", "bar")
        .query_param("hello", "world")
        .header_append_raw("Custom-Header1", "value2".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("bar".to_string()), json_value["args"]["foo"]);
    assert_eq!(Value::String("world".to_string()), json_value["args"]["hello"]);
}

#[test]
fn rest_client_header_append_raw_custom_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .header_append_raw("Custom-Header1", "value1".to_owned())
        .header_append_raw("Custom-Header1", "value2".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("value1,value2".to_string()), json_value["headers"]["Custom-Header1"]);
}

#[test]
fn rest_client_header_append_raw_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .header_append_raw("Accept", "text/html".to_owned())
        .header_append_raw("Accept", "application/xml".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("text/html,application/xml".to_string()), json_value["headers"]["Accept"]);
}

#[test]
fn rest_client_header_set_raw_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .header_set_raw("Accept", vec!["application/xhtml".to_owned()])
        .header_set_raw("Accept", vec!["text/html".to_owned(), "application/xml".to_owned()])
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("text/html,application/xml".to_string()), json_value["headers"]["Accept"]);
}

#[test]
fn rest_client_specified_accept_should_overwrite_json_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .accept(hyper::header::qitem(mime::Mime(hyper::mime::TopLevel::Text, hyper::mime::SubLevel::Html, vec![])))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("text/html".to_string()), json_value["headers"]["Accept"]);
}

#[test]
fn rest_client_default_json_accept_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_string()), json_value["headers"]["Accept"]);
}

#[test]
fn rest_client_authorization_string_test() {
    setup();

    let authorization_header = "custom authorization header string";

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .authorization_string(authorization_header.to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String(authorization_header.to_string()), json_value["headers"]["Authorization"]);
}

#[test]
fn rest_client_authorization_bearer_test() {
    setup();

    let token = "QWxhZGRpbjpvcGVuIHNlc2FtZQ";
    let authorization_header = "Bearer ".to_string() + token;

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .authorization_bearer(token.to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String(authorization_header), json_value["headers"]["Authorization"]);
}

#[test]
fn rest_client_authorization_basic_test() {
    setup();

    let b64_string = encode("user1:password1");
    let authorization_header = "Basic ".to_string() + &b64_string;

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .authorization_basic("user1".to_owned(), "password1".to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String(authorization_header), json_value["headers"]["Authorization"]);
}

#[test]
fn rest_client_cookie_friendly_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .cookie("foo", "bar")
        .cookie("foo2", "bar2")
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("foo=bar; foo2=bar2".to_string()), json_value["headers"]["Cookie"]);
}

#[test]
fn rest_client_cookie_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/headers"))
        .cookie("foo", "bar")
        .cookie("foo2", "bar2")
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("foo=bar; foo2=bar2".to_string()), json_value["headers"]["Cookie"]);
}

#[test]
fn get_value_http_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let url = httpbin::to_full_http_url("/get");
    let response = RestClient::get(&url)
            .execute_on(&mut core)
            .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String(url),
               json_value["url"]);
}

#[test]
fn get_value_https_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_https_url("/get"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("localhost:8001".to_string()),
               json_value["headers"]["Host"]);
}

#[test]
fn get_value_gzip_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/gzip"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::Bool(true), json_value["gzipped"]);
}

#[test]
fn get_value_deflate_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/deflate"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::Bool(true), json_value["deflated"]);
}

#[test]
fn get_string_utf8_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/encoding/utf8"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let string_content = response.content().as_ref_string();
    assert!(string_content.len() > 100);
}

#[test]
fn get_for_content_custom_type_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let url = httpbin::to_full_http_url("/get");
    let response = RestClient::get(&url)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let custom_type = response.content().as_typed::<GetResponse>();
    println!("Custom type: {:?}", custom_type);
    assert_eq!(url, custom_type.unwrap().url);
}

#[test]
fn get_for_content_zero_content_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::get(&httpbin::to_full_http_url("/redirect-to?url=http://example.com"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Found);

    assert_eq!("http://example.com".to_string(), response.headers().get::<hyper::header::Location>().unwrap().to_string());
    assert_eq!(0, response.content().as_ref_string().len());
}
