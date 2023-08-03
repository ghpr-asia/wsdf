//! **wsdf** is a proc-macro based framework to generate Wireshark dissectors from your Rust data
//! types. Using wsdf, you can write dissectors in a declarative way, all from within Rust.
//!
//! Examples can be found in the
//! [GitHub repo](https://github.com/ghpr-asia/wsdf/tree/master/wsdf/examples/).
//!
//! * [Getting started](#getting-started)
//! * [Types](#types)
//!     * [Mapping](#mapping)
//!     * [User-defined types](#user-defined-types)
//!     * [Decoding enums](#decoding-enums)
//!     * [Lists](#lists)
//! * [Taps and custom displays](#taps-and-custom-displays)
//!     * [Using `Fields`](#using-fields)
//!     * [Custom displays](#custom-displays)
//!         * [`decode_with`](#decode_with)
//!         * [`consume_with`](#consume_with)
//! * [Calling subdissectors](#calling-subdissectors)
//! * [Attributes](#attributes)
//!     * [Protocol attributes](#protocol-attributes)
//!     * [Variant attributes](#variant-attributes)
//!     * [Field attributes](#field-attributes)
//!
//! # Getting started
//!
//! Wireshark dissector plugins are dynamic library files. Thus, wsdf is intended to be used from a
//! Rust library crate and built as a dynamic library.
//!
//! As a hello world example, the `lib.rs` file for a UDP dissector looks like this:
//!
//! ```rust
//! // lib.rs
//! wsdf::version!("0.0.1", 4, 0);
//!
//! #[derive(wsdf::Protocol)]
//! #[wsdf(decode_from = [("ip.proto", 17)])]
//! struct UDP {
//!     src_port: u16,
//!     dst_port: u16,
//!     length: u16,
//!     checksum: u16,
//!     #[wsdf(subdissector = ("udp.port", "dst_port", "src_port"))]
//!     payload: Vec<u8>,
//! }
//! ```
//!
//! * The **`wsdf::version!` macro** specifies the plugin version as 0.0.1, built for Wireshark
//! version 4.0.X. This information is required by Wireshark when loading the plugin.
//! * The protocol itself should **derive `wsdf::Protocol`**. Since this is UDP, we also register
//! ourselves to the `"ip.proto"` dissector table, and set up the `"udp.port"` dissector table for
//! subdissectors to use. More details about these annotations can be found in the sections below.
//!
//! We must also specify the crate type in `Cargo.toml`.
//!
//! ```toml
//! # Cargo.toml
//! [lib]
//! crate-type = ["cdylib"]
//! ```
//!
//! After running `cargo build`, our dissector plugin should appear in the `target/debug/` folder
//! as a shared library object (`.so` on Linux, `.dylib` on macOS, and `.dll` on Windows). We can
//! then copy this file to Wireshark's [plugin
//! folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) so that
//! Wireshark or tshark will load it upon startup. On Linux, this is at
//! `~/.local/lib/wireshark/plugins/4.0/epan/`.
//!
//! # Types
//!
//! ## Mapping
//!
//! wsdf automatically maps some Rust types to Wireshark types.
//!
//! Rust type              | WS type    | WS encoding      | WS display
//! -----------------------|------------|------------------|-----------------------------------------
//! `u8` to `u64`          | `FT_UINT*` | `ENC_BIG_ENDIAN` | `BASE_DEC`
//! `i8` to `i64`          | `FT_INT*`  | `ENC_BIG_ENDIAN` | `BASE_DEC`
//! `Vec<u8>` or `[u8; _]` | `FT_BYTES` | `ENC_NA`         | `SEP_COLON \| BASE_SHOW_ASCII_PRINTABLE`
//!
//! ## User-defined types
//!
//! Each user-defined type must derive `ProtocolField`.
//!
//! ```rust
//! #[derive(wsdf::Protocol)]
//! #[wsdf(decode_from = "moldudp64.payload")]
//! struct MyProtocol {
//!     header: Header,
//! }
//!
//! #[derive(wsdf::ProtocolField)]
//! struct Header {
//!     src_port: u16,
//!     dst_port: u16,
//!     sequence: SequenceNumber,
//! }
//!
//! #[derive(wsdf::ProtocolField)]
//! struct SequenceNumber(u64);
//! ```
//!
//! Yout may use structs or enums as fields, but their contents must either be named fields or a
//! unit tuple. Something like `struct PortPair(u16, u16)` cannot derive `Protocol` or
//! `ProtocolField`.
//!
//! The root type which derives `Protocol` must be a struct.
//!
//! ## Decoding enums
//!
//! For enum fields, wsdf needs some help to know which variant to continue decoding the packet as.
//! For now, the variant to use must be determined by a prior field, and the enum type must
//! implement a method to determine the variant by returning the "index" of the selected variant.
//! This method must be named `dispatch_*` by convention, where `*` is the field's name.
//!
//! ```rust
//! #[derive(wsdf::ProtocolField)]
//! struct PacketInfo {
//!     typ: u8,
//!     #[wsdf(dispatch_field = "typ")]
//!     data: Data,
//! }
//!
//! #[derive(wsdf::ProtocolField)]
//! enum Data {
//!     Foo(u8),
//!     Bar(u16),
//!     Baz,
//! }
//!
//! impl Data {
//!     fn dispatch_typ(typ: &u8) -> usize {
//!         match *typ {
//!             b'F' => 0, // Foo
//!             b'B' => 1, // Bar
//!             _ => 2,    // Baz
//!         }
//!     }
//! }
//! ```
//!
//! For large enums, it may be difficult to track the "indices" of each variant. Thus, wsdf
//! provides a `Dispatch` helper macro.
//!
//! ```rust
//! # #[derive(wsdf::ProtocolField)]
//! # struct PacketInfo {
//! #     typ: u8,
//! #     #[wsdf(dispatch_field = "typ")]
//! #     data: Data,
//! # }
//! #[derive(wsdf::ProtocolField, wsdf::Dispatch)]
//! enum Data {
//!     Foo(u8),
//!     Bar(u16),
//!     Baz,
//! }
//!
//! impl Data {
//!     fn dispatch_typ(typ: &u8) -> DataDispatch {
//!         use DataDispatch::*;
//!         match *typ {
//!             b'F' => Foo,
//!             b'B' => Bar,
//!             _ => Baz,
//!         }
//!     }
//! }
//! ```
//!
//! This generates a new enum named `DataDispatch` which implements `Into<usize>`. We can just
//! directly return that from the `dispatch_typ` function.
//!
//! ## Lists
//!
//! wsdf understands arrays and `Vec`s. You would use a `Vec` if the number of elements is unknown
//! at compile time, but provided by another field in the protocol.
//!
//! ```rust
//! #[derive(wsdf::Protocol)]
//! #[wsdf(decode_from = "udp.port")]
//! struct MoldUDP64 {
//!     session: [u8; 10],
//!     sequence: u64,
//!     message_count: u16,
//!     #[wsdf(len_field = "message_count")]
//!     messages: Vec<MessageBlock>,
//! }
//! # #[derive(wsdf::ProtocolField)]
//! # struct MessageBlock {
//! #     len: u16,
//! #     #[wsdf(len_field = "len")]
//! #     data: Vec<u8>,
//! # }
//! ```
//!
//! # Taps and custom displays
//!
//! wsdf features a `tap` attribute which allows you to register some function(s) to be called
//! whenever the field is decoded. These functions follow the [Axum style magic
//! function](https://github.com/alexpusch/rust-magic-function-params) parameter passing approach.
//! Each function just needs to declare their parameters based on whatever they are interested in.
//!
//! The possible parameter types are:
//!
//! * [`Field`](tap::Field), the value of the field
//! * [`Fields`](tap::Fields), a map of the fields encountered so far
//! * [`Offset`](tap::Offset), the current byte offset into the packet
//! * [`Packet`](tap::Packet), the raw bytes of the packet
//! * [`PacketNanos`](tap::PacketNanos), the nanosecond timestamp at which the packet was recorded
//!
//! Any permutation of the parameters is supported.
//!
//! ```rust
//! use wsdf::tap::{Field, PacketNanos};
//!
//! #[derive(wsdf::ProtocolField)]
//! struct IpAddr (
//!     #[wsdf(tap = ["log_ts", "check_loopback", "slow_down"])]
//!     [u8; 4],
//! );
//!
//! fn log_ts(PacketNanos(ts): PacketNanos) {
//!     eprintln!("received a packet at {ts} nanoseconds");
//! }
//! fn check_loopback(Field(addr): Field<&[u8]>) {
//!     if addr == &[127, 0, 0, 1] {
//!         eprintln!("is loopback address");
//!     }
//! }
//! fn slow_down() {
//!     std::thread::sleep(std::time::Duration::from_millis(100));
//! }
//! ```
//!
//! In this example, wsdf will invoke `log_ts`, `check_loopback`, and `slow_down`, in that order,
//! when we encounter the field. Each function passed to the `tap` attribute must return `()`.
//!
//! ## Using `Fields`
//!
//! Fields can be marked for saving via the `#[wsdf(save)]` attribute. We can then access their
//! values through the [`Fields`](tap::Fields) parameter, which holds a key value store. The key to
//! each field is the Wireshark filter for that field, automatically generated by wsdf. You can
//! double check the filter for each field in Wireshark under `View` > `Internals` > `Supported
//! Protocols`.
//!
//! ```rust
//! use wsdf::tap::Fields;
//!
//! #[derive(wsdf::Protocol)]
//! #[wsdf(decode_from = "moldudp64.payload")]
//! struct MarketByPrice {
//!     nanos: u64,
//!     #[wsdf(save)]
//!     num_updates: u8,
//!     #[wsdf(len_field = "num_updates")]
//!     updates: Vec<PriceUpdate>,
//! }
//!
//! #[derive(wsdf::ProtocolField)]
//! struct PriceUpdate {
//!     side: u8,
//!     #[wsdf(save)]
//!     price: i32,
//!     #[wsdf(save, tap = "peek")]
//!     quantity: u64,
//! }
//!
//! fn peek(Fields(fields): Fields) {
//!     // `nanos` is an Option<&u64>, but we did not save it, so it should be `None`
//!     let nanos = fields.get_u64("market_by_price.nanos");
//!     assert_eq!(nanos, None);
//!
//!     // `num_updates` is an Option<&u8>, and since we saved it, it should be a `Some`
//!     let num_updates = fields.get_u8("market_by_price.num_updates");
//!     assert!(matches!(num_updates, Some(_)));
//!
//!     // `prices` is a `&[i32]`.
//!     let prices = fields.get_i32_multi("market_by_price.updates.price");
//!     // Do something with the values...
//! }
//! ```
//!
//! ## Custom displays
//!
//! By default, wsdf does not perform any additional formatting on fields. All formatting and
//! display is handled by Wireshark. However, you may wish to customize the way some fields appear
//! in the UI. wsdf enables this via the `decode_with` and `consume_with` attributes, which are
//! similar to taps. Their main differences from taps are
//!
//! * You can only have one `decode_with` or `consume_with` per field
//! * `decode_with` functions must return something implementing `Display`
//! * `consume_with` functions must return `(usize, T)` where `T` is anything implementing
//! `Display`
//!
//! ### `decode_with`
//!
//! You may use `decode_with` to customize how a field appears in Wireshark's UI.
//!
//! ```rust
//! use wsdf::tap::Field;
//!
//! #[derive(wsdf::ProtocolField)]
//! struct Order {
//!     #[wsdf(decode_with = "decode_side")]
//!     side: [u8; 1],
//!     price: i32,
//!     quantity: u64,
//! }
//!
//! fn decode_side(Field(side): Field<&[u8]>) -> &'static str {
//!     match side[0] {
//!         b'B' => "Bid",
//!         b'A' => "Ask",
//!         _ => "Unknown",
//!     }
//! }
//! ```
//!
//! By default, the `side` field will appear as an ascii byte string in the UI (`B`, `A`). The
//! `decode_side` function takes the value of `side` and returns a more user friendly display.
//!
//! In this example, our `decode_side` function returned a `&'static str`. But it can be anything
//! which implements `Display`, so `String`, `Box<dyn Display>`, etc. are all okay.
//!
//! ### `consume_with`
//!
//! The `consume_with` attribute is intended for bytes in the network where the size is not known
//! beforehand. This may appear for fields which use TLV style encoding. You can see an example of
//! this in the sample [DNS
//! dissector](https://github.com/ghpr-asia/wsdf/tree/master/wsdf/examples/dns.rs). The function
//! must return the number of bytes consumed for the field, as well as how to display it in
//! Wireshark.
//!
//! ```rust
//! use wsdf::tap::{Offset, Packet};
//!
//! #[derive(wsdf::ProtocolField)]
//! struct MyProto {
//!     #[wsdf(consume_with = "consume_bytes")]
//!     xs: Vec<u8>,
//! }
//!
//! fn consume_bytes(Offset(offset): Offset, Packet(pkt): Packet) -> (usize, String) {
//!     // Use the combination of the current offset and raw bytes from
//!     // `Packet` to manually parse these bytes.
//!     unimplemented!()
//! }
//! ```
//!
//! # Calling subdissectors
//!
//! For lower level protocols, you would want to hand the packet's payload to a subdissector. There
//! are two ways to achieve this - using a "Decode As" subdissector or using a regular dissector
//! table.
//!
//! The first variant can be seen in the MoldUDP64 dissector.
//!
//! ```rust
//! #[derive(wsdf::ProtocolField)]
//! struct MessageBlock {
//!     message_length: u16,
//!     #[wsdf(len_field = "message_length", subdissector = "moldudp64.payload")]
//!     message_data: Vec<u8>,
//! }
//! ```
//!
//! Whichever dissector has been registered to the pattern `"moldudp64.payload"` will be invoked
//! with the payload bytes.
//!
//! The second variant can be seen in the UDP dissector.
//!
//! ```rust
//! #[derive(wsdf::Protocol)]
//! #[wsdf(decode_from = [("ip.proto", 17)])]
//! struct UDP {
//!     src_port: u16,
//!     dst_port: u16,
//!     length: u16,
//!     checksum: u16,
//!     #[wsdf(subdissector = ("udp.port", "src_port", "dst_port"))]
//!     payload: Vec<u8>,
//! }
//! ```
//!
//! Here, we set up the `"udp.port"` dissector table, and try to find a subdissector registered to
//! the table, for the value of the source port. If that fails, we try again with the destination
//! port. And if that fails, Wireshark's default data dissector is invoked.
//!
//! # Attributes
//!
//! Attributes are used to customize fields or provide additional information. They can appear on
//! the protocol root, user-defined types, enum variants, and individual fields.
//!
//! ## Protocol attributes
//!
//! * `#[wsdf(decode_from = ["foo.payload", ("foo.port", 30000, ...)])]`
//!
//! Specifies the dissector table(s) to register the dissector with. Each value is one of
//!
//! A single string, e.g. `"moldudp64.payload"` uses the "Decode As" table.
//!
//! A tuple like `("udp.port", 30000, 30001)` registers the dissector to be used for UDP port
//! values 30000 and 30001.
//!
//! * `#[wsdf(proto_desc = "...")]`
//!
//! Full protocol description. This is used in the packet list pane.
//!
//! * `#[wsdf(proto_name = "...")]`
//!
//! Short protocol name. This is used in the packet details pane.
//!
//! * `#[wsdf(proto_filter = "...")]`
//!
//! Protocol name used in the display filter.
//!
//! ## Type-level attributes
//!
//! These attributes can appear on any type which derives `Protocol` or `ProtocolField`.
//!
//! * `#[wsdf(pre_dissect = "...")]`
//! * `#[wsdf(pre_dissect = ["...", ...])]`
//!
//! Provide path(s) to function(s) to call *before* the first field of the type is dissected. The
//! functions' parameters follow the same rules as taps.
//!
//! * `#[wsdf(post_dissect = "...")]`
//! * `#[wsdf(post_dissect = ["...", ...])]`
//!
//! Provide path(s) to function(s) to call *after* the last field of the type is dissected. The
//! functions' parameters follow the same rules as taps.
//!
//! ## Variant attributes
//!
//! * `#[wsdf(rename = "...")]`
//!
//! Custom name for the variant when displayed in Wireshark. See the sample DNS dissector for
//! examples.
//!
//! ## Field attributes
//!
//! * `#[wsdf(rename = "...")]`
//!
//! Custom name for the field when displayed in Wireshark.
//!
//! * `#[wsdf(hide)]`
//!
//! Hide the field, so it is not displayed in Wireshark.
//!
//! * `#[wsdf(save)]`
//!
//! Mark a field to be saved, such that it becomes accessible from the [`Fields`](tap::Fields)
//! parameter. See the section on [Using `Fields`](#using-fields) for more information.
//!
//! * `#[wsdf(len_field = "...")]`
//!
//! Intended for fields of type `Vec<_>`. Must point to a prior integer field which specifies the
//! number of elements for the field.
//!
//! * `#[wsdf(typ = "...")]`
//!
//! Specifies a Wireshark type to map the field to. Sensible mappings are chosen for most types,
//! e.g. `FT_UINT8` for `u8`, `FT_BYTES` for `[u8; _]`. However, a specific type can be selected
//! this way. The full list of field types can be found in Wireshark's `README.dissector` file.
//!
//! * `#[wsdf(enc = "...")]`
//!
//! Specifies an encoding for the field, e.g. `ENC_LITTLE_ENDIAN`. *By default, all integer fields
//! are encoded as big endian.* The full list of encodings and where they are applicable can be
//! found in Wireshark's `README.dissector` file.
//!
//! * `#[wsdf(display = "...")]`
//! * `#[wsdf(display = "..." | "...")]`
//!
//! Specifies a Wireshark display hint, e.g. `BASE_HEX`. The full list of possible values can be
//! found in Wireshark's `README.dissector` file.
//!
//! Note that this attribute permits a "bitwise-or" syntax to emulate the C API, e.g. you may use
//! `#[wsdf(display = "SEP_COLON" | "BASE_SHOW_ASCII_PRINTABLE")]` to mean "try to decode the bytes
//! as ascii characters, failing which, show them as regular octets separated by a colon".
//!
//! * `#[wsdf(dispatch_field = "...")]`
//!
//! For enum fields, specifies a previous field which is used to determine the variant. The enum
//! type must implement a corresponding method to receive this field and return an integer
//! representing the variant (the first is 0, the next is 1, etc.). See the section on [Decoding
//! enums](#decoding-enums) for more information.
//!
//! * `#[wsdf(tap = "...")]`
//! * `#[wsdf(tap = ["...", ...])]`
//!
//! Specifies the path to function(s) to inspect the packet. See the section on
//! [Taps](#taps-and-custom-displays) for more information.
//!
//! * `#[wsdf(decode_with = "...")]`
//!
//! Specifies the path to a function which takes the field's value as an argument and returns how
//! to display that field in Wireshark. Used to customize how fields are shown in the UI. See the
//! section on [Custom displays](#custom-displays) for details.
//!
//! * `#[wsdf(consume_with = "...")]`
//!
//! Specifies the path to a function which takes a slice of the entire packet and an offset, and
//! returns the number of bytes consumed and how to display the field. This is used for fields with
//! funky encoding schemes where you are unable to know its size beforehand.
//!
//! An example of this can be seen in the sample DNS dissector. See the section on
//! [Custom displays](#custom-displays) for details.
//!
//! * `#[wsdf(subdissector = "foo.payload")]`
//! * `#[wsdf(subdissector = ("foo.port", "dst_port", "src_port", ...))]`
//!
//! Specify subdissectors to try for payloads, i.e. it is meant for fields of type `Vec<u8>` only.
//! You can use two variants.
//!
//! The first variant, with a single string, tries a "Decode As" subdissector.  You must configure
//! this via the "Decode As" menu or the `decode_as_entries` configuration file. This is used in
//! the MoldUDP64 example.
//!
//! The second variant sets up a regular dissector table named by the first value (`"foo.port"` in
//! the example above). Each field listed afterwards is used to try and find a subdissector
//! registered to the table and field's value, one by one, until the first success. This is used in
//! the UDP example.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};

pub use epan_sys;
pub use wsdf_derive::{version, Dispatch, Protocol, ProtocolField};

/// Relevant to enum types only. Represents how the variant should be picked.
#[doc(hidden)]
pub enum VariantDispatch {
    Index(usize),
    None,
}

#[doc(hidden)]
pub enum HfMapOp<'a> {
    Set(&'a str, *mut c_int),
    Get(&'a str),
}

#[doc(hidden)]
pub enum SubdissectorMapOp<'a> {
    Set(&'a str, epan_sys::dissector_table_t),
    Get(&'a str),
    SetDecodeAs(&'a str, epan_sys::dissector_table_t),
    GetDecodeAs(&'a str),
}

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct HfMap(RefCell<HashMap<String, *mut c_int>>);

impl HfMap {
    pub fn accept(&self, op: HfMapOp) -> Option<c_int> {
        match op {
            HfMapOp::Set(key, val) => {
                let mut hfs = self.0.borrow_mut();
                hfs.insert(key.to_string(), val).map(|p| unsafe { *p })
            }
            HfMapOp::Get(key) => {
                let hfs = self.0.borrow();
                hfs.get(key).map(|p| unsafe { **p })
            }
        }
    }
}

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct SubdissectorMap {
    regular: RefCell<HashMap<String, epan_sys::dissector_table_t>>,
    decode_as: RefCell<HashMap<String, epan_sys::dissector_table_t>>,
}

impl SubdissectorMap {
    pub fn accept(&self, op: SubdissectorMapOp) -> Option<epan_sys::dissector_table_t> {
        use SubdissectorMapOp::*;
        match op {
            Set(key, val) => {
                let mut subdissectors = self.regular.borrow_mut();
                subdissectors.insert(key.to_string(), val)
            }
            Get(key) => {
                let subdissectors = self.regular.borrow();
                subdissectors.get(key).cloned()
            }
            SetDecodeAs(key, val) => {
                let mut subdissectors = self.decode_as.borrow_mut();
                subdissectors.insert(key.to_string(), val)
            }
            GetDecodeAs(key) => {
                let subdissectors = self.decode_as.borrow();
                subdissectors.get(key).cloned()
            }
        }
    }
}

#[cfg(test)]
mod test_static_maps {
    use super::*;

    #[test]
    fn hf_map_thread_local_is_ok() {
        // This aims to test the way we actually use the static maps, which is via thread local
        // storage.
        thread_local! {
            static HF_MAP: HfMap = HfMap::default();
        }

        let got = HF_MAP.with(|hfs| hfs.accept(HfMapOp::Get("foo")));
        assert!(got.is_none());

        let val = 7 as c_int;

        let got = HF_MAP.with(|hfs| hfs.accept(HfMapOp::Set("foo", &val as *const _ as *mut _)));
        assert!(got.is_none());

        let got = HF_MAP.with(|hfs| hfs.accept(HfMapOp::Get("foo")));
        assert_eq!(got.unwrap(), 7);
    }
}

macro_rules! wrap_pointer {
    ($name:ident, $($typ:ident)::+) => {
        #[derive(Debug, Clone, Copy)]
        #[doc(hidden)]
        pub struct $name(*const $($typ)::+);
        impl $name {
            pub const fn new(p: *const $($typ)::+) -> Self {
                Self(p)
            }
            pub const fn null() -> Self {
                Self(std::ptr::null())
            }
            pub fn unwrap_or(&self, p: *const $($typ)::+) -> *const $($typ)::+ {
                if self.0.is_null() {
                    p
                } else {
                    self.0
                }
            }
        }

        // This is OK for us (dissector runs in one thread only).
        unsafe impl std::marker::Sync for $name {}
    }
}

wrap_pointer!(SubtreeLabel, c_char); // label for text nodes
wrap_pointer!(FieldIdent, c_char); // field name
wrap_pointer!(FieldBlurb, c_char); // field description

/// A data type whose fields can be registered in Wireshark and dissected. *Not intended for public
/// use*.
pub trait ProtocolField {
    #[allow(clippy::too_many_arguments)]
    fn dissect<'a>(
        __wsdf_start: c_int,
        __wsdf_tvb: *mut epan_sys::tvbuff,
        __wsdf_parent: *mut epan_sys::_proto_node,
        __wsdf_prefix: &str,
        __wsdf_dispatch: VariantDispatch,
        __wsdf_subtree_label: SubtreeLabel,
        __wsdf_tvb_buf: &'a [u8],
        __wsdf_pinfo: *mut epan_sys::_packet_info,
        __wsdf_proto_tree_root: *mut epan_sys::_proto_node,
        __wsdf_fields_store: &mut FieldsStore<'a>,
    ) -> c_int;

    fn register(
        __wsdf_prefix: &str,
        __wsdf_proto_id: c_int,
        __wsdf_field_ident: FieldIdent,
        __wsdf_field_blurb: FieldBlurb,
    );

    fn ett() -> c_int;

    fn proto_id() -> &'static mut c_int;

    fn hf_map(op: HfMapOp) -> Option<c_int>;

    fn subdissector_map(op: SubdissectorMapOp) -> Option<epan_sys::dissector_table_t>;
}

/// A data type which represents the root of the protocol. *Not intended for public use.*
pub trait Protocol: ProtocolField {
    #[allow(clippy::missing_safety_doc)]
    unsafe extern "C" fn dissect_main(
        __wsdf_tvb: *mut epan_sys::tvbuff,
        __wsdf_pinfo: *mut epan_sys::_packet_info,
        __wsdf_tree: *mut epan_sys::_proto_node,
        __wsdf_data: *mut c_void,
    ) -> c_int;

    extern "C" fn proto_register();

    extern "C" fn proto_reg_handoff();
}

/// Helper types to work with taps, inspired by Axum's magic functions.
///
/// Although the module is called "tap", it is used in multiple places in wsdf, beyond the `tap`
/// attribute.
///
/// See <https://github.com/alexpusch/rust-magic-function-params> for how the magic parameter
/// passing stuff works.
pub mod tap {
    use crate::FieldsStore;

    /// A context holding packet information we might care about. *Meant for internal use*.
    #[derive(Clone)]
    #[doc(hidden)]
    pub struct Context<'a, T: Clone> {
        pub field: T,
        pub fields: &'a FieldsStore<'a>,
        pub pinfo: *mut epan_sys::_packet_info,
        pub packet: &'a [u8],
        pub offset: usize,
    }

    trait FromContext<'a, T: Clone> {
        fn from_ctx(ctx: &Context<'a, T>) -> Self;
    }

    /// The current field, if any. The absence of a value is represented by `Field(())`.
    ///
    /// ```rust
    /// # use wsdf::tap::Field;
    /// # use wsdf::ProtocolField;
    /// #[derive(ProtocolField)]
    /// struct MyProto {
    ///     #[wsdf(tap = "log_port")]
    ///     src_port: u16,
    /// }
    /// fn log_port(Field(port): Field<u16>) {
    ///     println!("Received packet from port {port}");
    /// }
    /// ```
    pub struct Field<T: Clone>(pub T);
    /// A key value store of previous fields encountered and saved. Each key is the Wireshark
    /// filter for that field.
    pub struct Fields<'a>(pub &'a FieldsStore<'a>);
    /// The nanosecond timestamp recorded in the packet capture data.
    pub struct PacketNanos(pub i64);
    /// Raw bytes of the packet.
    pub struct Packet<'a>(pub &'a [u8]);
    /// Current offset into the packet.
    ///
    /// You probably want to use this in combination with [`Packet`] to index and slice the packet
    /// data.
    pub struct Offset(pub usize);

    impl<T: Clone> FromContext<'_, T> for Field<T> {
        fn from_ctx(ctx: &Context<T>) -> Self {
            Self(ctx.field.clone())
        }
    }

    impl<T: Clone> FromContext<'_, T> for PacketNanos {
        fn from_ctx(ctx: &Context<T>) -> Self {
            let abs_ts = unsafe { (*ctx.pinfo).abs_ts };
            Self(abs_ts.secs * 1e9 as i64 + abs_ts.nsecs as i64)
        }
    }

    impl<'a, T: Clone> FromContext<'a, T> for Fields<'a> {
        fn from_ctx(ctx: &Context<'a, T>) -> Self {
            Self(ctx.fields)
        }
    }

    impl<'a, T: Clone> FromContext<'a, T> for Packet<'a> {
        fn from_ctx(ctx: &Context<'a, T>) -> Self {
            Self(ctx.packet)
        }
    }

    impl<T: Clone> FromContext<'_, T> for Offset {
        fn from_ctx(ctx: &Context<T>) -> Self {
            Self(ctx.offset)
        }
    }

    #[doc(hidden)]
    pub trait Handler<'a, T: Clone, Args, Ret> {
        fn call(self, ctx: &Context<'a, T>) -> Ret;
    }

    macro_rules! impl_handler {
        ($($arg:ident),*) => {
            impl<'a, F, T, $($arg,)* Ret> Handler<'a, T, ($($arg,)*), Ret> for F
            where
                F: Fn($($arg,)*) -> Ret,
                T: Clone,
                $($arg: FromContext<'a, T>,)*
            {
                fn call(self, _ctx: &Context<'a, T>) -> Ret {
                    (self)($($arg::from_ctx(_ctx)),*)
                }
            }
        };
    }

    impl_handler!();
    impl_handler!(Arg);
    impl_handler!(Arg1, Arg2);
    impl_handler!(Arg1, Arg2, Arg3);
    impl_handler!(Arg1, Arg2, Arg3, Arg4);
    impl_handler!(Arg1, Arg2, Arg3, Arg4, Arg5);

    #[doc(hidden)]
    pub fn handle_tap<'a, T, Args, H>(ctx: &Context<'a, T>, handler: H)
    where
        T: Clone,
        H: Handler<'a, T, Args, ()>,
    {
        handler.call(ctx)
    }

    #[doc(hidden)]
    pub fn handle_decode_with<'a, T, Args, Ret, H>(ctx: &Context<'a, T>, handler: H) -> Ret
    where
        T: Clone,
        H: Handler<'a, T, Args, Ret>,
        Ret: std::fmt::Display,
    {
        handler.call(ctx)
    }

    #[doc(hidden)]
    pub fn handle_consume_with<'a, Args, Ret, H>(ctx: &Context<'a, ()>, handler: H) -> (usize, Ret)
    where
        H: Handler<'a, (), Args, (usize, Ret)>,
        Ret: std::fmt::Display,
    {
        handler.call(ctx)
    }
}

pub type FieldsMap<T> = HashMap<String, Vec<T>>;

/// A key-value store of fields saved. Each type is kept in its own multimap.
#[derive(Default)]
pub struct FieldsStore<'a> {
    u8s: FieldsMap<u8>,
    u16s: FieldsMap<u16>,
    u32s: FieldsMap<u32>,
    u64s: FieldsMap<u64>,
    i8s: FieldsMap<i8>,
    i16s: FieldsMap<i16>,
    i32s: FieldsMap<i32>,
    i64s: FieldsMap<i64>,
    bytes: FieldsMap<&'a [u8]>,
}

impl FieldsStore<'_> {
    fn get_first<'a, T>(fields: &'a FieldsMap<T>, filter: &str) -> Option<&'a T> {
        fields.get(filter).and_then(|xs| xs.first())
    }
    fn get_multi<'a, T>(fields: &'a FieldsMap<T>, filter: &str) -> Option<&'a [T]> {
        fields.get(filter).map(|xs| xs.as_slice())
    }
    pub fn get_u8(&self, filter: &str) -> Option<&u8> {
        Self::get_first(&self.u8s, filter)
    }
    pub fn get_u8_multi(&self, filter: &str) -> Option<&[u8]> {
        Self::get_multi(&self.u8s, filter)
    }
    pub fn get_u16(&self, filter: &str) -> Option<&u16> {
        Self::get_first(&self.u16s, filter)
    }
    pub fn get_u16_multi(&self, filter: &str) -> Option<&[u16]> {
        Self::get_multi(&self.u16s, filter)
    }
    pub fn get_u32(&self, filter: &str) -> Option<&u32> {
        Self::get_first(&self.u32s, filter)
    }
    pub fn get_u32_multi(&self, filter: &str) -> Option<&[u32]> {
        Self::get_multi(&self.u32s, filter)
    }
    pub fn get_u64(&self, filter: &str) -> Option<&u64> {
        Self::get_first(&self.u64s, filter)
    }
    pub fn get_u64_multi(&self, filter: &str) -> Option<&[u64]> {
        Self::get_multi(&self.u64s, filter)
    }
    pub fn get_i8(&self, filter: &str) -> Option<&i8> {
        Self::get_first(&self.i8s, filter)
    }
    pub fn get_i8_multi(&self, filter: &str) -> Option<&[i8]> {
        Self::get_multi(&self.i8s, filter)
    }
    pub fn get_i16(&self, filter: &str) -> Option<&i16> {
        Self::get_first(&self.i16s, filter)
    }
    pub fn get_i16_multi(&self, filter: &str) -> Option<&[i16]> {
        Self::get_multi(&self.i16s, filter)
    }
    pub fn get_i32(&self, filter: &str) -> Option<&i32> {
        Self::get_first(&self.i32s, filter)
    }
    pub fn get_i32_multi(&self, filter: &str) -> Option<&[i32]> {
        Self::get_multi(&self.i32s, filter)
    }
    pub fn get_i64(&self, filter: &str) -> Option<&i64> {
        Self::get_first(&self.i64s, filter)
    }
    pub fn get_i64_multi(&self, filter: &str) -> Option<&[i64]> {
        Self::get_multi(&self.i64s, filter)
    }
    pub fn get_bytes(&self, filter: &str) -> Option<&[u8]> {
        Self::get_first(&self.bytes, filter).copied()
    }
    pub fn get_bytes_multi(&self, filter: &str) -> Option<&[&[u8]]> {
        Self::get_multi(&self.bytes, filter)
    }
    pub fn insert_u8(&mut self, filter: &str, value: u8) {
        self.u8s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_u16(&mut self, filter: &str, value: u16) {
        self.u16s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_u32(&mut self, filter: &str, value: u32) {
        self.u32s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_u64(&mut self, filter: &str, value: u64) {
        self.u64s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_i8(&mut self, filter: &str, value: i8) {
        self.i8s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_i16(&mut self, filter: &str, value: i16) {
        self.i16s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_i32(&mut self, filter: &str, value: i32) {
        self.i32s.entry(filter.to_string()).or_default().push(value);
    }
    pub fn insert_i64(&mut self, filter: &str, value: i64) {
        self.i64s.entry(filter.to_string()).or_default().push(value);
    }
}

impl<'a> FieldsStore<'a> {
    pub fn insert_bytes(&mut self, filter: &str, value: &'a [u8]) {
        self.bytes
            .entry(filter.to_string())
            .or_default()
            .push(value);
    }
}

#[cfg(test)]
mod compile_tests {
    #[test]
    fn run_all() {
        let t = trybuild::TestCases::new();

        t.pass("tests/simple/*.rs");
        t.pass("tests/should_pass/*.rs");

        t.compile_fail("tests/should_fail/*.rs");
    }
}
