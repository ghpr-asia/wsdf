// Tests that the derive macro fails when a compulsory container attribute is missing

use wsdf::*;

#[derive(Protocol)]
struct MyProtocol {
    foo: u32,
}

fn main() {}
