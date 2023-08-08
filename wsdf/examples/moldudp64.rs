#![allow(dead_code)]

use wsdf::{protocol, version, Dissect, Proto};

version!("0.0.1", 4, 0);
protocol!(BabyMoldUDP64);

#[derive(Dissect, Proto)]
#[wsdf(
    proto_desc = "Baby MoldUDP64 by wsdf",
    proto_name = "Baby MoldUDP64",
    proto_filter = "baby_moldudp64",
    decode_from = "udp.port"
)]
struct BabyMoldUDP64 {
    #[wsdf(bytes)]
    session: [u8; 10],
    sequence_number: u64,
    message_count: u16,
    #[wsdf(len_field = "message_count")]
    messages: Vec<MessageBlock>,
}

#[derive(Dissect)]
struct MessageBlock {
    message_length: u16,
    #[wsdf(
        bytes,
        len_field = "message_length",
        subdissector = "baby_moldudp64.payload"
    )]
    message_data: Vec<u8>,
}
