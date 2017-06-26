#[macro_use] extern crate serde_derive;
extern crate tokio_core;

extern crate serde_json;
extern crate hyper;
extern crate roadrunner;

// need both RestClient and RestClientMethods
use roadrunner::RestClient;
use roadrunner::RestClientMethods;

use hyper::StatusCode;
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Address {
    street: String,
    city: String,
}

fn main () {
    let mut core = tokio_core::reactor::Core::new().unwrap();

    let original_typed = Address {
        street: "135 College View Ave.".to_owned(),
        city: "San Francisco".to_owned(),
    };

    let response = RestClient::post("http://mockbin.com/request")
        .cookie("food", "bar")
        .authorization_bearer("QWxhZGRpbjpvcGVuIHNlc2FtZQ".to_string())
        .json_body_typed(&original_typed)
        .execute_on(&mut core)
        .unwrap();

    println!("{:?}", response);

    assert_eq!(*response.status(), StatusCode::Ok);

    let json_value = response.content().as_value().unwrap();
    assert_eq!(Value::String("application/json".to_owned()),
    json_value["headers"]["content-type"]);

    let data_str = json_value["postData"]["text"].as_str().unwrap();

    println!("data_str : {:?}", data_str);

    let response_typed: Address = serde_json::from_str(data_str).unwrap();
    assert_eq!(original_typed, response_typed);
}