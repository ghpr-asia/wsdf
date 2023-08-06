//! Use this file to test out the new #[derive(Dissect)] macro.

#![allow(dead_code)]

use wsdf::Dissect;

#[derive(Dissect)]
struct Udp {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(bytes)]
    payload: Vec<u8>,
}

#[derive(Dissect)]
struct UnixNanos(u64);

fn main() {}
