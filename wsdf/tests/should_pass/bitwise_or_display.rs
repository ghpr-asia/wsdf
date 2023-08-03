#![allow(dead_code)]

// Tests that the display meta item accepts a bitwise OR

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: u64,
    #[wsdf(display = "SEP_COLON" | "BASE_SHOW_ASCII_PRINTABLE")]
    baz: [u8; 9],
}

fn main() {}
