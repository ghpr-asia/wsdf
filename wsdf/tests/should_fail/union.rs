// Tests that unions cannot derive Protocol

use wsdf::*;

#[derive(Protocol)]
union MyUnion {
    f1: u32,
    f2: f32,
}

fn main() {}
