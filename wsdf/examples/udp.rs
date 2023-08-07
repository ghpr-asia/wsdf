#![allow(dead_code)]

use wsdf::{protocol, version, Dissect, Proto};

protocol!(Udp);
version!("0.0.1", 4, 0);

// The ip.proto field obtained from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby UDP by wsdf",
    proto_name = "Baby UDP",
    proto_filter = "baby_udp",
    decode_from = [("ip.proto", 17)],
)]
struct Udp {
    src_port: u16,
    #[wsdf(save, tap = "nop")]
    dst_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(bytes, subdissector = ("baby_udp.port", "src_port", "dst_port"))]
    payload: Vec<u8>,
}

fn nop() {}
