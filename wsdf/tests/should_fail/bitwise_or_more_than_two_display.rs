// Tests that the display meta item does not accept bitwise OR with > 2 strs

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: u64,
    #[wsdf(display = "SEP_COLON" | "BASE_SHOW_ASCII_PRINTABLE" | "SEP_SPACE")]
    baz: [u8; 9],
}

fn main() {}
