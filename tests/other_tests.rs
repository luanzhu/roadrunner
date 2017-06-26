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
use hyper::StatusCode;
use serde_json::Value;

mod httpbin;

fn setup() {
   let _ = env_logger::init();
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Address {
    street: String,
    city: String,
}

#[test]
fn rest_client_delete_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let url = httpbin::to_full_http_url("/delete");
    let response = RestClient::delete(&url)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String(url),
    json_value["url"]);
}

#[test]
fn rest_client_json_body_typed_patch_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let original_typed = Address {
        street: "135 College View Ave.".to_owned(),
        city: "Greenville".to_owned(),
    };

    let response = RestClient::patch(&httpbin::to_full_http_url("/patch"))
        .json_body_typed(&original_typed)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_owned()), json_value["headers"]["Content-Type"]);

    let data_str = json_value["data"].as_str().unwrap();

    println!("data_str : {:?}", data_str);

    let response_typed: Address = serde_json::from_str(data_str).unwrap();
    assert_eq!(original_typed, response_typed);
}


#[test]
fn rest_client_json_body_typed_put_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let original_typed = Address {
        street: "135 College View Ave.".to_owned(),
        city: "Greenville".to_owned(),
    };

    let response = RestClient::put(&httpbin::to_full_http_url("/put"))
        .json_body_typed(&original_typed)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_owned()), json_value["headers"]["Content-Type"]);

    let data_str = json_value["data"].as_str().unwrap();

    println!("data_str : {:?}", data_str);

    let response_typed: Address = serde_json::from_str(data_str).unwrap();
    assert_eq!(original_typed, response_typed);
}

#[test]
fn rest_client_options_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::options(&httpbin::to_full_http_url("/headers"))
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let allow_methods = response.headers().get::<hyper::header::Allow>().unwrap().as_slice();
    let allow_set: std::collections::HashSet<&hyper::Method> = allow_methods.iter().collect();
    assert!(allow_set.contains(&hyper::Method::Head));
    assert!(allow_set.contains(&hyper::Method::Get));
    assert!(allow_set.contains(&hyper::Method::Options));
}

#[test]
fn rest_client_json_body_typed_post_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let original_typed = Address {
        street: "135 College View Ave.".to_owned(),
        city: "Greenville".to_owned(),
    };

    let response = RestClient::post(&httpbin::to_full_http_url("/post"))
        .json_body_typed(&original_typed)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_owned()), json_value["headers"]["Content-Type"]);

    let data_str = json_value["data"].as_str().unwrap();

    println!("data_str : {:?}", data_str);

    let response_typed: Address = serde_json::from_str(data_str).unwrap();
    assert_eq!(original_typed, response_typed);
}

#[test]
fn rest_client_json_body_str_post_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let json_str = r#"{ "hello": "world" }"#;

    let response = RestClient::post(&httpbin::to_full_http_url("/post"))
        .json_body_str(json_str.to_owned())
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_owned()), json_value["headers"]["Content-Type"]);

    let data_str = json_value["data"].as_str().unwrap();

    println!("data_str : {:?}", data_str);

    let json_value_got_back: Value = serde_json::from_str(data_str).unwrap();
    println!("json value got back: {:?}", json_value_got_back);

    assert_eq!(Value::String("world".to_string()), json_value_got_back["hello"]);
}

#[test]
fn rest_client_form_field_post_test() {
    setup();

    let mut core = tokio_core::reactor::Core::new().unwrap();

    let response = RestClient::post(&httpbin::to_full_http_url("/post"))
        .query_param("question1", "hello")
        .form_field("foo", "bar1")
        .form_field("foo", "bar2")
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::Array(vec![Value::String("bar1".to_string()),
                                 Value::String("bar2".to_owned())]), json_value["form"]["foo"]);
}
