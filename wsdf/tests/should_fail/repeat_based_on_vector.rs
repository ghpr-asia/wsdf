// Tests what happens if we try to have a vector repeat on a vector?

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    n: u32,
    #[wsdf(len_field = "n")]
    xs: Vec<u32>,
    #[wsdf(len_field = "xs")]
    ys: Vec<u32>,
}

fn main() {}
