#![allow(dead_code)]

// Tests that ProtocolFields which are a unit tuple can have field options are allowed to have
// field options

use wsdf::*;

#[derive(Protocol)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    time: TimeStamp,
}

// This declares a re-usable TimeStamp type. Note that we cannot do something like `type TimeStamp
// = u32` as we can't implement external traits on primitive types.
#[derive(ProtocolField)]
struct TimeStamp(
    #[wsdf(
        typ = "FT_ABSOLUTE_TIME",
        enc = "ENC_TIME_SECS",
        display = "ABSOLUTE_TIME_LOCAL"
    )]
    u32,
);

fn main() {}
