#![allow(dead_code)]

// Tests that field types which are a unit tuple struct work fine

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    foo: Foo,
}

#[derive(ProtocolField)]
struct Foo(u8);

fn main() {}
