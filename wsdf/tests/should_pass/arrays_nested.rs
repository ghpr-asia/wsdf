#![allow(dead_code)]

// Tests that nested array fields can compile

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: [[u64; 10]; 10],
    baz: [[Bar; 10]; 10],
}

#[derive(ProtocolField)]
struct Bar {
    qux: u64,
}

fn main() {}
