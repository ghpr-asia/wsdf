#![allow(dead_code)]

use wsdf::{version, Protocol};

version!("0.0.1", 4, 0);

// The ip.proto field obtained from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

fn heuristic_f() -> bool {
    true
}

#[derive(Protocol)]
#[wsdf(
    proto_desc = "Baby udp HD by wsdf",
    proto_name = "Baby udp HD",
    proto_filter = "baby_udp_hd",
    decode_from = [("ip.proto", 17)],
    heuristic,
    heuristic_fn = "heuristic_f"
)]
struct BabyUDPHD {
    source_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(subdissector = ("baby_udp_hd.port", "dest_port", "source_port"))]
    payload: Vec<u8>,
}
