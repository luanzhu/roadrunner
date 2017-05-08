# Roadrunner (RR)

Roadrunner is a rust rest client based on [hyper project](https://github.com/hyperium/hyper) to 
provide an user friendly interface for use.

The API interface is partially inspired by [unirest java library](http://unirest.io/java.html).

# Why?

I recently started to look at rust and noticed the choice of rest client in rust seemed to be
limited. Hyper client and some libcurl bindings I tried seem to be pretty low level to me.

Another big reason is that writing a library (no matter how small it is) seems to be a good
way to start a new language. :)

# Example
```
#[macro_use] extern crate serde_derive;
extern crate tokio_core;

extern crate serde_json;
extern crate hyper;
extern crate roadrunner;

// need both RestClient and RestClientMethods
use roadrunner::RestClient;
use roadrunner::RestClientMethods;

use hyper::status::StatusCode;
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
```

# Usage

## High level

High level API access is provided through **RestClient** and methods available in trait
**RestClientMethods**.

Please refer to tests in the tests folder for more example.

## Low level

For more control of request settings, use **request_for_response**.  The high level RestClient is
a thin layer on top of this function.

# Supported Methods

* GET
* POST
* PUT
* PATCH
* DELETE
* OPTIONS

# Run integration tests in tests folder?

All integration tests use httpbin to verify requests.  However, because of [a recent regression
in httpbin](https://github.com/kennethreitz/httpbin/issues/340), httpbin cannot see the request
body transferred in chunks.

Before that bug is fixed or tests are migrated to mockbin, one has to run the **start.sh** in
the docker-httpbin to start two containers (one for httpbin and another one for nginx) locally
before you run any integration tests.

## Add self-signed SSL cert into your CA

Hyper client relies on [rust-native-tls]((https://github.com/sfackler/rust-native-tls) to
handle https connections.  However, there is no easy option to allow self-signed certs yet.
There is [an open issue regarding this](https://github.com/sfackler/rust-native-tls/issues/13).

As a result, the self-signed cert used in docker (docker-httpbin/config/localhost.cert) has to
be set to trusted (or added to trusted CA store).  Otherwise, one test will fail.

# References

Some parts of implementations are based on ideas/examples from:

* [Hyper client example](https://github.com/hyperium/hyper/blob/master/examples/client.rs)
* [Get Data From A URL in Rust](http://hermanradtke.com/2015/09/21/get-data-from-a-url-rust.html)

# Related

* [hyper](https://github.com/hyperium/hyper)
* [tokio-curl](https://github.com/tokio-rs/tokio-curl)

