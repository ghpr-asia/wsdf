#![allow(dead_code)]

// Tests that we can use types in other modules as fields on the protocol

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    foo: foo::Foo,
}

mod foo {
    use wsdf::*;

    #[derive(ProtocolField)]
    pub struct Foo {
        bar: bar::Bar,
    }

    mod bar {
        use wsdf::*;

        #[derive(ProtocolField)]
        pub struct Bar {
            x: u8,
        }
    }
}

fn main() {}
