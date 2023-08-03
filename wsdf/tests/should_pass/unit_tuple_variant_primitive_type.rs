#![allow(dead_code)]

// Tests that variants of unit tuple with primitive types work

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    typ: u8,
    #[wsdf(dispatch_field = "typ")]
    bar: Bar,
}

#[derive(ProtocolField)]
enum Bar {
    Foo(u8),
    Qux(Qux),
}

impl Bar {
    fn dispatch_typ(_typ: &u8) -> usize {
        unimplemented!()
    }
}

#[derive(ProtocolField)]
struct Qux {
    baz: u8,
}

fn main() {}
