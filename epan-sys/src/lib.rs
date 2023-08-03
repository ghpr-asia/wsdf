#![doc = include_str!("../README.md")]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// We do this to suppress compiler warnings and minimize terminal spam. Just know that they are all
// related to u128.
#![allow(improper_ctypes)]
#![allow(clippy::all)]

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings.rs"));
