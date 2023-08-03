#![allow(dead_code)]

// Tests that structs can derive Protocol

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: u64,
    baz: [u8; 9],
}

fn main() {}
