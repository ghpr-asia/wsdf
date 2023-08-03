#![allow(dead_code)]

use wsdf::{Protocol, ProtocolField};

#[derive(Protocol)]
#[wsdf(decode_from = "udp.port", pre_dissect = "f", post_dissect = "g")]
struct Foo {
    bar: Bar,
}

#[derive(ProtocolField)]
#[wsdf(pre_dissect = "f", post_dissect = ["f", "g"])]
struct Bar(u16);

use wsdf::tap::Fields;

fn f() {}
fn g(_fs: Fields) {}

fn main() {}
