#![allow(dead_code)]

use wsdf::tap::{Field, FieldsLocal, Offset, Packet};
use wsdf::{protocol, version, Dissect, Proto};

version!("0.0.1", 4, 0);
protocol!(BabyDns);

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby DNS by wsdf",
    proto_name = "Baby DNS",
    proto_filter = "baby_dns",
    decode_from = [("udp.port", 53)],
)]
struct BabyDns {
    identification: u16,
    flags: u16,
    #[wsdf(rename = "Number of Questions")]
    number_of_questions: u16,
    #[wsdf(rename = "Number of Answers")]
    number_of_answers: u16,
    #[wsdf(rename = "Number of Authority RRs")]
    number_of_authority_rrs: u16,
    #[wsdf(rename = "Number of Additional RRs")]
    number_of_additional_rrs: u16,
    #[wsdf(len_field = "number_of_questions")]
    questions: Vec<Question>,
    #[wsdf(len_field = "number_of_answers")]
    answers: Vec<ResourceRecord>,
    #[wsdf(len_field = "number_of_authority_rrs")]
    domain_authority: Vec<ResourceRecord>,
    #[wsdf(len_field = "number_of_additional_rrs")]
    additional_information: Vec<ResourceRecord>,
}

#[derive(Dissect)]
struct Question {
    name: CharStr,
    #[wsdf(decode_with = "decode_qtype", rename = "Type")]
    type_: u16,
    #[wsdf(decode_with = "decode_class")]
    class: u16,
}

#[derive(Dissect)]
struct ResourceRecord {
    name: CharStr,
    #[wsdf(save, decode_with = "decode_qtype", rename = "Type")]
    type_: u16,
    #[wsdf(decode_with = "decode_class")]
    class: u16,
    #[wsdf(rename = "TTL")]
    ttl: Seconds,
    #[wsdf(rename = "RR Data Length")]
    rdlength: u16,
    #[wsdf(get_variant = "get_rdata_type", rename = "RR Data")]
    rdata: Rdata,
}

fn get_rdata_type(FieldsLocal(store): FieldsLocal) -> &'static str {
    let ty = store.get_u16("type_").unwrap();
    match ty {
        1 => "A",
        2 => "NS",
        5 => "Cname",
        6 => "Soa",
        12 => "Ptr",
        15 => "MX",
        28 => "Aaaa",
        _ => "Unknown",
    }
}

#[derive(Dissect)]
enum Rdata {
    #[wsdf(rename = "A (Host address)")]
    A(#[wsdf(typ = "FT_IPv4", display = "BASE_NETMASK")] u32),
    #[wsdf(rename = "NS (Authoritative name server)")]
    NS(
        /// Specifies a host which should be authoritative for the specified class and domain.
        CharStr,
    ),
    #[wsdf(rename = "CNAME (Canonical name)")]
    Cname(
        /// Specifies the canonical or primary name for the owner. The owner name is an alias.
        CharStr,
    ),
    #[wsdf(rename = "SOA (Start of authority zone)")]
    Soa {
        /// Domain name of the the name server that was the original or primary source of data for
        /// this zone.
        mname: CharStr,
        /// Specifies the mailbox of the person responsible for this zone.
        rname: CharStr,
        /// The unsigned 32 bit version number of the original copy of the zone.
        serial: u32,
        /// Time interval before the zone should be refreshed.
        refresh: Seconds,
        /// Time interval that should elapse before a failed refresh should be retried.
        retry: Seconds,
        /// Time value that specifies the upper limit on the time interval that can elapse before
        /// the zone is no longer authoritative.
        expire: Seconds,
        /// Minimum TTL field that should be exported with any RR from this zone.
        minimum: Seconds,
    },
    #[wsdf(rename = "PTR (Domain name pointer)")]
    Ptr(
        /// Points to some location in the domain name space.
        CharStr,
    ),
    #[wsdf(rename = "MX (Mail exchange)")]
    MX {
        /// Specifies the preference given to this RR among others at the same owner. Lower values
        /// are preferred.
        preference: u16,
        /// Specifies a host willing to act as a mail exchange for the owner name.
        mail_exchanger: CharStr,
    },
    #[wsdf(rename = "AAAA (IPv6 address)")]
    Aaaa(#[wsdf(bytes, typ = "FT_IPv6", display = "BASE_NONE")] [u8; 16]),
    // To keep this example simple, we ignore the other resource records.
    Unknown(#[wsdf(bytes, consume_with = "drain_rdata")] Vec<u8>),
}

/// Represents the stringy fields in DNS. We isolate it into its own type because its decoding is
/// slightly complex. See CharStr::consume.
#[derive(Dissect)]
struct CharStr(#[wsdf(bytes, consume_with = "CharStr::consume")] Vec<u8>);

impl CharStr {
    // Slightly convoluted, see https://www.zytrax.com/books/dns/ch15/#answer
    fn consume(Packet(packet): Packet, Offset(offset): Offset) -> (usize, String) {
        if offset >= packet.len() {
            return (
                0,
                format!("Unexpected EOF (expected more bytes at offset {})", offset),
            );
        }

        if packet[offset] & 0b11000000 != 0 {
            let mut p: u16 = 0;
            p += (0b00111111 & packet[offset]) as u16;
            p <<= 8;
            p |= packet[offset + 1] as u16;

            let (_, ret) = Self::consume(Packet(packet), Offset(p as usize));
            return (2, ret);
        }

        let mut i = offset;
        let mut ret = String::new();

        loop {
            if packet[i] & 0b11000000 != 0 {
                i += 2;
                break;
            }

            let n = packet[i] as usize;
            if n == 0 {
                i += 1;
                break;
            }

            let s = std::str::from_utf8(&packet[i + 1..i + 1 + n]).unwrap_or("<invalid utf8>");
            ret.push_str(s);
            ret.push('.');
            i += 1 + n;
        }

        ret.pop(); // pop the trailing '.'

        (i - offset, ret)
    }
}

fn decode_class(Field(x): Field<u16>) -> String {
    // See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    let s = match x {
        1 => "Internet (1)",
        3 => "Chaos (3)",
        4 => "Hesoid (4)",
        _ => return format!("Unknown ({})", x),
    };
    s.to_string()
}

fn decode_qtype(Field(x): Field<u16>) -> String {
    // See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    let s = match x {
        1 => "A [Host address] (1)",
        2 => "NS [Authoritative name server] (2)",
        5 => "CNAME [Canonical name for an alias] (5)",
        6 => "SOA [Start of a zone of authority] (6)",
        12 => "PTR [Domain name pointer] (12)",
        15 => "MX [Mail exchange] (15)",
        28 => "AAAA [IP6 address] (28)",
        _ => return format!("Unknown ({})", x),
    };
    s.to_string()
}

#[derive(Dissect)]
struct Seconds(#[wsdf(decode_with = "Seconds::decode")] u32);

impl Seconds {
    fn decode(Field(s): Field<u32>) -> String {
        let seconds = s % 60;
        let minutes = (s / 60) % 60;
        let hours = (s / 60) / 60;

        if hours > 0 {
            format!("{} hr, {} min, {} sec", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{} min, {} sec", minutes, seconds)
        } else {
            format!("{} sec", seconds)
        }
    }
}

/// Drain all the data which belongs to a resource record.
fn drain_rdata(Packet(packet): Packet, Offset(offset): Offset) -> (usize, &'static str) {
    // The number of bytes in the RR is stored in the previous two bytes.
    let n = u16::from_be_bytes([packet[offset - 2], packet[offset - 1]]) as usize;
    let n = n.clamp(0, packet.len() - offset);
    (n, "Gave up on decoding (╯°□°)╯︵ ┻━┻")
}
