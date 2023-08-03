#![allow(dead_code)]

use wsdf::{version, Protocol};

version!("0.0.1", 4, 0);

// The ip.proto field obtained from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

#[derive(Protocol)]
#[wsdf(
    proto_desc = "Baby UDP by wsdf",
    proto_name = "Baby UDP",
    proto_filter = "baby_udp",
    decode_from = [("ip.proto", 17)],
)]
struct BabyUDP {
    source_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(subdissector = ("baby_udp.port", "dest_port", "source_port"))]
    payload: Vec<u8>,
}
