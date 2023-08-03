#![allow(dead_code)]

// Tests that structs with nested structs work fine (in case our code generation gets confused
// somewhere between structs which are fields and the root struct)

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: Bar,
    qux: u32,
}

#[derive(ProtocolField)]
struct Bar {
    baz: u64,
    bat: [u8; 9],
}

fn main() {}
