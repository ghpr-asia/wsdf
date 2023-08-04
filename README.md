[![docs.rs](https://img.shields.io/badge/docs.rs-wsdf-latest)](https://docs.rs/wsdf)
[![crates.io](https://img.shields.io/crates/v/wsdf.svg)](https://crates.io/crates/wsdf)
[![CI](https://github.com/ghpr-asia/wsdf/actions/workflows/ci.yml/badge.svg)](https://github.com/ghpr-asia/wsdf/actions/workflows/ci.yml)

**wsdf** (**W**ire**s**hark **D**issector **F**ramework) is a proc-macro based
framework to generate Wireshark dissectors from your Rust data types. Using
wsdf, you can write dissectors in a declarative way, all from within Rust.

Here is what a dissector for UDP looks like:

```rust
#[derive(wsdf::Protocol)]
#[wsdf(decode_from = [("ip.proto", 17)])]
struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(subdissector = ("udp.port", "dst_port", "src_port"))]
    payload: Vec<u8>,
}
```

Check out the [docs](https://docs.rs/wsdf) for more information. Some
[examples](wsdf/examples/) are also available, including a simple dissector for
DNS, showcased below.

![DNS dissector showcase](https://raw.githubusercontent.com/ghpr-asia/wsdf/main/docs/dns_dissector.gif)

wsdf has been tested on Linux against Wireshark 4.0.

**License**

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
