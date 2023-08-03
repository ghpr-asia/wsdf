// Tests that unknown container attributes are rejected

use wsdf::*;

#[derive(Protocol)]
#[wsdf(foo = "bar")] // Unknown meta item
struct MyProtocol {
    foo: u32,
}

fn main() {}
