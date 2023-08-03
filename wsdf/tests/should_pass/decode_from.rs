#![allow(dead_code)]

// Tests that the decode_from = [("some.thing", 420)] is accepted

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = [("udp.port", 1234), "udp.payload"])]
struct ProtoFoo {
    bar: u64,
    baz: [u8; 9],
}

fn main() {}
