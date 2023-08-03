// Tests that if we try to dispatch on a struct value that it fails. There is no  *real* reason for
// this apart from keeping our implementation simple for now.

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: Bar,
    #[wsdf(dispatch_field = "bar")]
    qux: Qux,
}

struct Bar {
    baz: u32,
}

enum Qux {
    Hot,
    Cold,
}

impl Qux {
    fn dispatch_bar(bar: &Bar) -> usize {
        0
    }
}

fn main() { }
