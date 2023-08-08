//! **wsdf** (**W**ire**s**hark **D**issector **F**ramework) is a proc-macro based framework to
//! generate Wireshark dissectors from your Rust data types. Using wsdf, you can write dissectors
//! in a declarative way, all from within Rust.
//!
//! Examples can be found in the
//! [GitHub repo](https://github.com/ghpr-asia/wsdf/tree/main/wsdf/examples/).
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
//! * The protocol itself should **derive `wsdf::Protocol`**. Since this is UDP, the dissector is
//! registered to the `"ip.proto"` dissector table, and also sets up the `"udp.port"` dissector
//! table for subdissectors to use. More details about these annotations can be found in the
//! sections below.
//!
//! The crate type must be specified in `Cargo.toml`.
//!
//! ```toml
//! # Cargo.toml
//! [lib]
//! crate-type = ["cdylib"]
//! ```
//!
//! After running `cargo build`, the dissector plugin should appear in the `target/debug/` folder
//! as a shared library object (`.so` on Linux, `.dylib` on macOS, and `.dll` on Windows). Copying
//! this file to Wireshark's [plugin
//! folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) will allow
//! Wireshark or tshark to load it upon startup. On Linux, this is at
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
//! You may use structs or enums as fields, but their contents must either be named fields or a
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
//! This generates a new enum named `DataDispatch` which implements `Into<usize>`, which can be
//! directly returned from the `dispatch_typ` function.
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
//! when it encounters the field. Each function passed to the `tap` attribute must return `()`.
//!
//! ## Using `Fields`
//!
//! Fields can be marked for saving via the `#[wsdf(save)]` attribute. You can then access their
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
//!     // `nanos` is an Option<&u64>, but it is not saved, so it should be `None`
//!     let nanos = fields.get_u64("market_by_price.nanos");
//!     assert_eq!(nanos, None);
//!
//!     // `num_updates` is an Option<&u8>, and it is saved, it should be a `Some`
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
//! Here, the `"udp.port"` dissector table is set up. To decode the payload, wsdf will first try to
//! find a subdissector registered to the `"udp.port"` table interested in the value of the source
//! port. If no subdissector is found, wsdf tries again with the destination port. And if that
//! fails, Wireshark's default data dissector is invoked.
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
use std::ffi::{c_char, c_int, c_uint, c_void, CString};

pub use epan_sys;
pub use wsdf_derive::{protocol, version, Dispatch, Dissect, Proto, Protocol, ProtocolField};

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
    #[derive(Clone, Copy)]
    #[doc(hidden)]
    pub struct Context<'a, T: Clone> {
        pub field: T,
        pub fields: &'a FieldsStore<'a>,
        pub fields_local: &'a FieldsStore<'a>,
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
    pub struct FieldsLocal<'a>(pub &'a FieldsStore<'a>);
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

    impl<'a, T: Clone> FromContext<'a, T> for FieldsLocal<'a> {
        fn from_ctx(ctx: &Context<'a, T>) -> Self {
            Self(ctx.fields_local)
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
    impl_handler!(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6);

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
    pub fn handle_consume_with<'a, T, Args, Ret, H>(
        ctx: &Context<'a, T>,
        handler: H,
    ) -> (usize, Ret)
    where
        T: Clone,
        H: Handler<'a, T, Args, (usize, Ret)>,
        Ret: std::fmt::Display,
    {
        handler.call(ctx)
    }

    pub fn handle_get_variant<'a, Args, H>(ctx: &Context<'a, ()>, handler: H) -> &'static str
    where
        H: Handler<'a, (), Args, &'static str>,
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

/// Collection of data which may be needed when dissecting a type.
///
/// Let's keep this type trivially copy-able.
#[derive(Clone, Copy)]
pub struct DissectorArgs<'a, 'tvb> {
    /// The previously registered header field indices. Keyed by wireshark's filter strings.
    pub hf_indices: &'tvb HfIndices,

    /// The previously registered ett indices. Keyed by wireshark's filter strings.
    pub etts: &'tvb EttIndices,

    pub dtables: &'tvb DissectorTables,

    pub tvb: *mut epan_sys::tvbuff,
    pub pinfo: *mut epan_sys::packet_info,
    pub proto_root: *mut epan_sys::proto_tree,

    /// A slice of the entire packet.
    pub data: &'tvb [u8],

    /// Wireshark filter string for the next expected field.
    pub prefix: &'a str,

    /// Last segment of the prefix, corresponding to the field's portion.
    pub prefix_local: &'a str,

    /// Offset at which the next field is expected.
    pub offset: usize,

    /// Parent node under which the next field should be added.
    pub parent: *mut epan_sys::proto_tree,

    /// A dispatch index, iff the field is an enum.
    pub variant: Option<&'static str>,

    /// The length of the field, iff the field is a list with length determined at runtime.
    pub list_len: Option<usize>,

    /// Encoding for the field, if any.
    pub ws_enc: Option<u32>,
}

/// Data required when registering fields.
#[derive(Clone, Copy)]
pub struct RegisterArgs<'a> {
    /// The protocol ID.
    pub proto_id: c_int,

    /// Name for the field.
    pub name: *const c_char,

    /// Wireshark filter string for the field.
    pub prefix: &'a str,

    /// Description for the field. Would be a null pointer if there is no description.
    pub blurb: *const c_char,

    /// Custom picked wireshark type, if any.
    pub ws_type: Option<c_uint>,

    /// Custom picked wireshark display, if any.
    pub ws_display: Option<c_int>,
}

#[derive(Default)]
pub struct HfIndices(HashMap<String, c_int>);

#[derive(Default)]
pub struct EttIndices(HashMap<String, c_int>);

#[derive(Default)]
pub struct DissectorTables(HashMap<&'static str, *mut epan_sys::dissector_table>);

impl HfIndices {
    /// Creates a hf index for the current prefix as a text node. Intended for subtree roots with
    /// no associated type. If an index for the prefix already exists, simply returns it.
    pub fn get_or_create_text_node(&mut self, args: &RegisterArgs) -> c_int {
        if self.0.contains_key(args.prefix) {
            return self.0[args.prefix];
        }

        // Since this is a text node, the display type should be BASE_NONE, and the wireshark type
        // should be FT_NONE, if either of them happen to be set.
        debug_assert!(
            args.ws_display.is_none()
                || args.ws_display == Some(epan_sys::field_display_e_BASE_NONE as _)
        );
        debug_assert!(args.ws_type.is_none() || args.ws_type == Some(epan_sys::ftenum_FT_NONE));

        let idx = register_hf_index(
            args,
            epan_sys::field_display_e_BASE_NONE as _,
            epan_sys::ftenum_FT_NONE,
        );
        self.0.insert(args.prefix.to_string(), idx);
        idx
    }

    pub fn get(&self, prefix: &str) -> Option<c_int> {
        self.0.get(prefix).copied()
    }

    pub fn insert(&mut self, prefix: &str, idx: c_int) -> Option<c_int> {
        self.0.insert(prefix.to_string(), idx)
    }
}

impl EttIndices {
    /// Creates an ett index for the current prefix. If an index for the prefix already exists,
    /// simply returns it.
    pub fn get_or_create_ett(&mut self, args: &RegisterArgs) -> c_int {
        if self.0.contains_key(args.prefix) {
            return self.0[args.prefix];
        }
        let ett_index_ptr = Box::leak(Box::new(-1)) as *mut _;
        unsafe {
            epan_sys::proto_register_subtree_array([ett_index_ptr].as_mut_ptr(), 1);
        }
        let ett_index = unsafe { *ett_index_ptr };
        debug_assert_ne!(ett_index, -1);
        self.0.insert(args.prefix.to_string(), ett_index);
        ett_index
    }

    pub fn get(&self, prefix: &str) -> Option<c_int> {
        self.0.get(prefix).copied()
    }
}

impl DissectorTables {
    /// Tries to retrieve the pointer to a Decode As dissector table. If it is not found, registers
    /// one with Wireshark.
    pub fn get_or_create_decode_as(
        &mut self,
        proto_id: c_int,
        name: &'static str,
    ) -> *mut epan_sys::dissector_table {
        if self.0.contains_key(&name) {
            return self.0[&name];
        }
        let name_cstr = CString::new(name).unwrap();
        let table_ptr = unsafe {
            epan_sys::register_decode_as_next_proto(
                proto_id,
                name_cstr.as_ptr(),
                name_cstr.as_ptr(),
                None,
            )
        };
        self.0.insert(name, table_ptr);
        table_ptr
    }

    pub fn get_or_create_integer_table(
        &mut self,
        proto_id: c_int,
        name: &'static str,
        ws_type: c_uint,
        ws_display: c_int,
    ) -> *mut epan_sys::dissector_table {
        if self.0.contains_key(&name) {
            return self.0[&name];
        }
        let name_cstr =
            Box::leak(CString::new(name).unwrap().into_boxed_c_str()).as_ptr() as *const c_char;
        let table_ptr = unsafe {
            epan_sys::register_dissector_table(name_cstr, name_cstr, proto_id, ws_type, ws_display)
        };
        self.0.insert(name, table_ptr);
        table_ptr
    }

    pub fn get(&self, name: &'static str) -> Option<*mut epan_sys::dissector_table> {
        self.0.get(name).copied()
    }
}

pub struct WsIndices<'tvb> {
    pub hf: &'tvb mut HfIndices,
    pub ett: &'tvb mut EttIndices,
    pub dtable: &'tvb mut DissectorTables,
}

impl DissectorArgs<'_, '_> {
    /// Retrieves the hf index registered for the current prefix, if any.
    pub fn get_hf_index(&self) -> Option<c_int> {
        self.hf_indices.get(self.prefix)
    }

    /// Retrieves the ett index registered for the current prefix, if any.
    pub fn get_ett_index(&self) -> Option<c_int> {
        self.etts.get(self.prefix)
    }

    pub fn add_subtree(&self) -> *mut epan_sys::proto_item {
        let subtree_hf_index = self.get_hf_index().unwrap();
        let parent = unsafe {
            epan_sys::proto_tree_add_item(
                self.parent,
                subtree_hf_index,
                self.tvb,
                self.offset as _,
                -1,
                epan_sys::ENC_NA,
            )
        };
        unsafe {
            epan_sys::proto_registrar_get_name(subtree_hf_index);
            epan_sys::proto_item_add_subtree(parent, self.get_ett_index().unwrap());
        }
        parent
    }

    pub fn call_data_dissector(&self) -> usize {
        unsafe { epan_sys::call_data_dissector(self.tvb, self.pinfo, self.proto_root) as _ }
    }
}

pub trait Proto {
    #[allow(clippy::missing_safety_doc)]
    unsafe extern "C" fn dissect_main(
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::_packet_info,
        tree: *mut epan_sys::_proto_node,
        data: *mut c_void,
    ) -> c_int;

    #[allow(clippy::missing_safety_doc)]
    unsafe extern "C" fn register_protoinfo();

    #[allow(clippy::missing_safety_doc)]
    unsafe extern "C" fn register_handoff();
}

pub trait Dissect<'tvb, MaybeBytes: ?Sized> {
    /// We would like to query the value of some fields, e.g. `u8`. If the type supports this
    /// querying, we set its `Emit` type. Otherwise, `Emit` can be set to `()`.
    type Emit;

    /// Adds the field to the protocol tree. Must return the number of bytes dissected.
    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize;

    /// Returns the number of bytes this field occupies in the packet.    
    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize;

    /// Registers the field. It is the responsibility of the implementor to save the hf index
    /// and possibly the ett index into the two maps.
    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices);

    /// Returns the value associated with the field, if any.
    fn emit(args: &DissectorArgs<'_, 'tvb>) -> Self::Emit;
}

pub trait Primitive<'tvb, MaybeBytes: ?Sized>: Dissect<'tvb, MaybeBytes> {
    /// Adds the field to the protocol tree using a custom string.
    fn add_to_tree_format_value(
        args: &DissectorArgs<'_, 'tvb>,
        s: &impl std::fmt::Display,
        nr_bytes: usize,
    );

    /// Saves the field into the fields store.
    fn save<'a>(
        args: &DissectorArgs<'_, 'tvb>,
        gstore: &mut FieldsStore<'tvb>,
        lstore: &mut FieldsStore<'a>,
    ) where
        'tvb: 'a;
}

pub trait SubdissectorKey {
    fn create_table(proto_id: c_int, name: &'static str, dtables: &mut DissectorTables);

    fn try_subdissector(&self, args: &DissectorArgs, name: &'static str) -> usize;
}

pub trait Subdissect<'tvb>: Dissect<'tvb, [u8]> {
    fn try_subdissector(
        args: &DissectorArgs,
        name: &'static str,
        key: &impl SubdissectorKey,
    ) -> usize {
        key.try_subdissector(args, name)
    }

    fn setup_tvb_next(args: &DissectorArgs) -> *mut epan_sys::tvbuff;
}

fn setup_tvb_next_with_len(args: &DissectorArgs, len: Option<usize>) -> *mut epan_sys::tvbuff {
    let tvb_reported_len = unsafe { epan_sys::tvb_reported_length(args.tvb) as usize };
    let tvb_next_len = len.unwrap_or(tvb_reported_len - args.offset);
    unsafe { epan_sys::tvb_new_subset_length(args.tvb, args.offset as _, tvb_next_len as _) }
}

impl Subdissect<'_> for Vec<u8> {
    fn setup_tvb_next(args: &DissectorArgs) -> *mut epan_sys::tvbuff {
        setup_tvb_next_with_len(args, args.list_len)
    }
}

impl Subdissect<'_> for &[u8] {
    fn setup_tvb_next(args: &DissectorArgs) -> *mut epan_sys::tvbuff {
        setup_tvb_next_with_len(args, args.list_len)
    }
}

impl<const N: usize> Subdissect<'_> for [u8; N] {
    fn setup_tvb_next(args: &DissectorArgs) -> *mut epan_sys::tvbuff {
        setup_tvb_next_with_len(args, Some(N))
    }
}

fn dissector_try_uint(args: &DissectorArgs, name: &'static str, value: u32) -> usize {
    let subdissector = args.dtables.get(name).unwrap();
    unsafe {
        epan_sys::dissector_try_uint(subdissector, value, args.tvb, args.pinfo, args.proto_root)
            as _
    }
}

impl SubdissectorKey for () {
    fn create_table(proto_id: c_int, name: &'static str, dtables: &mut DissectorTables) {
        dtables.get_or_create_decode_as(proto_id, name);
    }

    fn try_subdissector(&self, args: &DissectorArgs, name: &'static str) -> usize {
        let subdissector = args.dtables.get(name).unwrap();
        unsafe {
            epan_sys::dissector_try_payload(subdissector, args.tvb, args.pinfo, args.proto_root)
                as _
        }
    }
}

impl SubdissectorKey for u16 {
    fn create_table(proto_id: c_int, name: &'static str, dtables: &mut DissectorTables) {
        dtables.get_or_create_integer_table(
            proto_id,
            name,
            epan_sys::ftenum_FT_UINT16,
            epan_sys::field_display_e_BASE_DEC as _,
        );
    }

    fn try_subdissector(&self, args: &DissectorArgs, name: &'static str) -> usize {
        dissector_try_uint(args, name, *self as _)
    }
}

impl<'tvb, MaybeBytes: ?Sized, T> Dissect<'tvb, MaybeBytes> for (T,)
where
    T: Dissect<'tvb, MaybeBytes>,
{
    type Emit = <T as Dissect<'tvb, MaybeBytes>>::Emit;

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <T as Dissect<'tvb, MaybeBytes>>::add_to_tree(args, fields)
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <T as Dissect<'tvb, MaybeBytes>>::size(args, fields)
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<'tvb, MaybeBytes>>::register(args, ws_indices);
    }

    fn emit(args: &DissectorArgs<'_, 'tvb>) -> Self::Emit {
        <T as Dissect<'tvb, MaybeBytes>>::emit(args)
    }
}

impl<'tvb, MaybeBytes: ?Sized, T> Primitive<'tvb, MaybeBytes> for (T,)
where
    T: Primitive<'tvb, MaybeBytes>,
{
    fn add_to_tree_format_value(
        args: &DissectorArgs<'_, 'tvb>,
        s: &impl std::fmt::Display,
        nr_bytes: usize,
    ) -> usize {
        <T as Primitive<'tvb, MaybeBytes>>::add_to_tree_format_value(args, s, nr_bytes)
    }

    fn save<'a>(
        args: &DissectorArgs<'_, 'tvb>,
        gstore: &mut FieldsStore<'tvb>,
        lstore: &mut FieldsStore<'a>,
    ) where
        'tvb: 'a,
    {
        <T as Primitive<'tvb, MaybeBytes>>::save(args, gstore, lstore);
    }
}

/// Adds a single field to the protocol tree. Internally, this uses the most basic
/// `proto_tree_add_item` function.
fn add_to_tree_single_field(args: &DissectorArgs, size: usize, default_enc: u32) {
    let hf_index = args.get_hf_index().unwrap();
    unsafe {
        epan_sys::proto_tree_add_item(
            args.parent,
            hf_index,
            args.tvb,
            args.offset as _,
            size as _,
            args.ws_enc.unwrap_or(default_enc),
        );
    }
}

/// Adds a uint type (u8, u16, etc.) to the protocol tree with a custom string.
fn add_to_tree_format_value_uint(
    args: &DissectorArgs,
    size: usize,
    value: c_uint,
    s: &impl std::fmt::Display,
) {
    let hf_index = args.get_hf_index().unwrap();
    let fmt = CString::new(ToString::to_string(s)).unwrap();
    unsafe {
        epan_sys::proto_tree_add_uint_format_value(
            args.parent,
            hf_index,
            args.tvb,
            args.offset as _,
            size as _,
            value,
            fmt.as_ptr(),
        );
    }
}

/// Adds an int type (i8, i16, etc.) to the protocol tree with a custom string.
fn add_to_tree_format_value_int(
    args: &DissectorArgs,
    size: usize,
    value: c_int,
    s: &impl std::fmt::Display,
) {
    let hf_index = args.get_hf_index().unwrap();
    let fmt = CString::new(ToString::to_string(s)).unwrap();
    unsafe {
        epan_sys::proto_tree_add_int_format_value(
            args.parent,
            hf_index,
            args.tvb,
            args.offset as _,
            size as _,
            value,
            fmt.as_ptr(),
        );
    }
}

/// Registers a hf index.
fn register_hf_index(args: &RegisterArgs, default_display: c_int, default_type: c_uint) -> c_int {
    let hf_index_ptr = Box::leak(Box::new(-1)) as *mut _;
    let abbrev =
        Box::leak(CString::new(args.prefix).unwrap().into_boxed_c_str()).as_ptr() as *const c_char;
    let type_ = args.ws_type.unwrap_or(default_type);
    let display = args.ws_display.unwrap_or(default_display);

    let hf_register_info = epan_sys::hf_register_info {
        p_id: hf_index_ptr,
        hfinfo: epan_sys::header_field_info {
            name: args.name,
            abbrev,
            type_,
            display,
            strings: std::ptr::null(),
            bitmask: 0,
            blurb: args.blurb,
            id: -1,
            parent: 0,
            ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
            same_name_prev_id: -1,
            same_name_next: std::ptr::null_mut(),
        },
    };
    let hfs = Box::leak(Box::new([hf_register_info])) as *mut _;

    unsafe {
        epan_sys::proto_register_field_array(args.proto_id, hfs, 1);
    }
    debug_assert_ne!(unsafe { *hf_index_ptr }, -1);
    unsafe { *hf_index_ptr }
}

const DEFAULT_INT_ENCODING: u32 = epan_sys::ENC_BIG_ENDIAN;
const DEFAULT_INT_DISPLAY: c_int = epan_sys::field_display_e_BASE_DEC as _;

impl Dissect<'_, ()> for () {
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 0, epan_sys::ENC_NA);
        0
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        0
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        let hf_index = register_hf_index(
            args,
            epan_sys::field_display_e_BASE_NONE as _,
            epan_sys::ftenum_FT_NONE,
        );
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(_args: &DissectorArgs) {}
}

impl<'tvb> Primitive<'tvb, ()> for () {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        let hf_index = args.get_hf_index().unwrap();
        let field_name = unsafe { epan_sys::proto_registrar_get_name(hf_index) };
        let fmt = CString::new(s.to_string()).unwrap();
        unsafe {
            epan_sys::proto_tree_add_none_format(
                args.parent,
                hf_index,
                args.tvb,
                args.offset as _,
                nr_bytes as _,
                "%s: %s\0".as_ptr() as *const c_char,
                field_name,
                fmt.as_ptr(),
            );
        }
    }

    fn save<'a>(_args: &DissectorArgs, _gstore: &mut FieldsStore, _lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        // nop
    }
}

impl Dissect<'_, ()> for u8 {
    type Emit = u8;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 1, DEFAULT_INT_ENCODING);
        1
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        1
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_UINT8;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> u8 {
        unsafe { epan_sys::tvb_get_guint8(args.tvb, args.offset as _) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for u8 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 1);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_uint(args, 1, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_u8(args.prefix, value);
        lstore.insert_u8(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for u16 {
    type Emit = u16;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 2, DEFAULT_INT_ENCODING);
        2
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        2
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_UINT16;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> u16 {
        unsafe { epan_sys::tvb_get_ntohs(args.tvb, args.offset as _) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for u16 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 2);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_uint(args, 2, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_u16(args.prefix, value);
        lstore.insert_u16(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for u32 {
    type Emit = u32;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 4, DEFAULT_INT_ENCODING);
        4
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        4
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_UINT32;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> u32 {
        unsafe { epan_sys::tvb_get_ntohl(args.tvb, args.offset as _) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for u32 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 4);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_uint(args, 4, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_u32(args.prefix, value);
        lstore.insert_u32(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for u64 {
    type Emit = u64;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 8, DEFAULT_INT_ENCODING);
        8
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        8
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_UINT64;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> u64 {
        unsafe { epan_sys::tvb_get_ntoh64(args.tvb, args.offset as _) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for u64 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 8);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_uint(args, 8, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_u64(args.prefix, value);
        lstore.insert_u64(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for i8 {
    type Emit = i8;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 1, DEFAULT_INT_ENCODING);
        1
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        1
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_INT8;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> i8 {
        unsafe { epan_sys::tvb_get_gint8(args.tvb, args.offset as _) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for i8 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 1);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_int(args, 1, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_i8(args.prefix, value);
        lstore.insert_i8(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for i16 {
    type Emit = i16;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 2, DEFAULT_INT_ENCODING);
        2
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        2
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_INT16;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> i16 {
        let enc = args.ws_enc.unwrap_or(DEFAULT_INT_ENCODING);
        unsafe { epan_sys::tvb_get_gint16(args.tvb, args.offset as _, enc) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for i16 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 2);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_int(args, 2, value, s);
    }
    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_i16(args.prefix, value);
        lstore.insert_i16(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for i32 {
    type Emit = i32;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 4, DEFAULT_INT_ENCODING);
        4
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        4
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_INT32;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> i32 {
        let enc = args.ws_enc.unwrap_or(DEFAULT_INT_ENCODING);
        unsafe { epan_sys::tvb_get_gint32(args.tvb, args.offset as _, enc) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for i32 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 4);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_int(args, 4, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_i32(args.prefix, value);
        lstore.insert_i32(args.prefix_local, value);
    }
}

impl Dissect<'_, ()> for i64 {
    type Emit = i64;

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        add_to_tree_single_field(args, 8, DEFAULT_INT_ENCODING);
        8
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        8
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_INT64;

        let hf_index = register_hf_index(args, DEFAULT_INT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs) -> i64 {
        let enc = args.ws_enc.unwrap_or(DEFAULT_INT_ENCODING);
        unsafe { epan_sys::tvb_get_gint64(args.tvb, args.offset as _, enc) }
    }
}

impl<'tvb> Primitive<'tvb, ()> for i64 {
    fn add_to_tree_format_value(args: &DissectorArgs, s: &impl std::fmt::Display, nr_bytes: usize) {
        debug_assert_eq!(nr_bytes, 8);

        let value = <Self as Dissect<'_, ()>>::emit(args) as _;
        add_to_tree_format_value_int(args, 8, value, s);
    }

    fn save<'a>(args: &DissectorArgs, gstore: &mut FieldsStore, lstore: &mut FieldsStore)
    where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'_, ()>>::emit(args);
        gstore.insert_i64(args.prefix, value);
        lstore.insert_i64(args.prefix_local, value);
    }
}

fn add_to_tree_format_value_bytes(
    args: &DissectorArgs,
    nr_bytes: usize,
    s: &impl std::fmt::Display,
) {
    let hf_index = args.get_hf_index().unwrap();
    let value = &args.data[args.offset..args.offset + nr_bytes];
    let fmt = CString::new(ToString::to_string(s)).unwrap();

    unsafe {
        epan_sys::proto_tree_add_bytes_format_value(
            args.parent,
            hf_index,
            args.tvb,
            args.offset as _,
            nr_bytes as _,
            value.as_ptr(),
            fmt.as_ptr(),
        );
    }
}

impl<'tvb, const N: usize> Dissect<'tvb, [u8]> for [u8; N] {
    type Emit = &'tvb [u8];

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore<'tvb>) -> usize {
        add_to_tree_single_field(args, N, epan_sys::ENC_NA);
        N
    }

    fn size(_args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        N
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        const DEFAULT_DISPLAY: c_int =
            (epan_sys::BASE_SHOW_ASCII_PRINTABLE | epan_sys::ENC_SEP_COLON) as _;
        const DEFAULT_TYPE: c_uint = epan_sys::ftenum_FT_BYTES;

        let hf_index = register_hf_index(args, DEFAULT_DISPLAY, DEFAULT_TYPE);
        ws_indices.hf.insert(args.prefix, hf_index);
    }

    fn emit(args: &DissectorArgs<'_, 'tvb>) -> &'tvb [u8] {
        &args.data[args.offset..args.offset + N]
    }
}

impl<'tvb, const N: usize> Primitive<'tvb, [u8]> for [u8; N] {
    fn add_to_tree_format_value(
        args: &DissectorArgs<'_, 'tvb>,
        s: &impl std::fmt::Display,
        nr_bytes: usize,
    ) {
        debug_assert_eq!(nr_bytes, N);

        add_to_tree_format_value_bytes(args, nr_bytes, s);
    }

    fn save<'a>(
        args: &DissectorArgs<'_, 'tvb>,
        gstore: &mut FieldsStore<'tvb>,
        lstore: &mut FieldsStore<'a>,
    ) where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'tvb, [u8]>>::emit(args);
        gstore.insert_bytes(args.prefix, value);
        lstore.insert_bytes(args.prefix_local, value);
    }
}

impl<'tvb> Dissect<'tvb, [u8]> for Vec<u8> {
    type Emit = &'tvb [u8];

    fn add_to_tree(args: &DissectorArgs, _fields: &mut FieldsStore<'tvb>) -> usize {
        let len = args.list_len.unwrap_or(args.data.len() - args.offset);
        add_to_tree_single_field(args, len, epan_sys::ENC_NA);
        len
    }

    fn size(args: &DissectorArgs, _fields: &mut FieldsStore) -> usize {
        // @todo: clarify this length thing
        args.list_len.unwrap_or(args.data.len() - args.offset)
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        // [u8; _] and Vec<u8> are the same when it comes to registration.
        <[u8; 0] as Dissect<[u8]>>::register(args, ws_indices);
    }

    fn emit(args: &DissectorArgs<'_, 'tvb>) -> &'tvb [u8] {
        // @todo: clarify this length thing
        let len = args.list_len.unwrap_or(args.data.len() - args.offset);
        &args.data[args.offset..args.offset + len]
    }
}

impl<'tvb> Primitive<'tvb, [u8]> for Vec<u8> {
    fn add_to_tree_format_value(
        args: &DissectorArgs<'_, 'tvb>,
        s: &impl std::fmt::Display,
        nr_bytes: usize,
    ) {
        debug_assert_eq!(nr_bytes, args.list_len.unwrap_or(nr_bytes));

        add_to_tree_format_value_bytes(args, nr_bytes, s);
    }

    fn save<'a>(
        args: &DissectorArgs<'_, 'tvb>,
        gstore: &mut FieldsStore<'tvb>,
        lstore: &mut FieldsStore<'a>,
    ) where
        'tvb: 'a,
    {
        let value = <Self as Dissect<'tvb, [u8]>>::emit(args);
        gstore.insert_bytes(args.prefix, value);
        lstore.insert_bytes(args.prefix_local, value);
    }
}

impl<'tvb> Dissect<'tvb, [u8]> for &[u8] {
    type Emit = &'tvb [u8];

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<u8> as Dissect<'tvb, [u8]>>::add_to_tree(args, fields)
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<u8> as Dissect<'tvb, [u8]>>::size(args, fields)
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <Vec<u8> as Dissect<'tvb, [u8]>>::register(args, ws_indices)
    }

    fn emit(args: &DissectorArgs<'_, 'tvb>) -> &'tvb [u8] {
        <Vec<u8> as Dissect<'tvb, [u8]>>::emit(args)
    }
}

impl<'tvb> Primitive<'tvb, [u8]> for &[u8] {
    fn add_to_tree_format_value(
        args: &DissectorArgs<'_, 'tvb>,
        s: &impl std::fmt::Display,
        nr_bytes: usize,
    ) {
        <Vec<u8> as Primitive<'tvb, [u8]>>::add_to_tree_format_value(args, s, nr_bytes);
    }

    fn save<'a>(
        args: &DissectorArgs<'_, 'tvb>,
        gstore: &mut FieldsStore<'tvb>,
        lstore: &mut FieldsStore<'a>,
    ) where
        'tvb: 'a,
    {
        <Vec<u8> as Primitive<'tvb, [u8]>>::save(args, gstore, lstore);
    }
}

impl<'tvb, T> Dissect<'tvb, ()> for Vec<T>
where
    T: Dissect<'tvb, ()>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..args.list_len.unwrap() {
            size += <T as Dissect<()>>::add_to_tree(args, fields);
        }
        size
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..args.list_len.unwrap() {
            size += <T as Dissect<'tvb, ()>>::size(args, fields);
        }
        size
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<()>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

impl<'tvb, T> Dissect<'tvb, [u8]> for Vec<T>
where
    T: Dissect<'tvb, [u8]>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..args.list_len.unwrap() {
            size += <T as Dissect<'tvb, [u8]>>::add_to_tree(args, fields);
        }
        size
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..args.list_len.unwrap() {
            size += <T as Dissect<'tvb, [u8]>>::size(args, fields);
        }
        size
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<[u8]>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

impl<'tvb, T, const N: usize> Dissect<'tvb, ()> for [T; N]
where
    T: Dissect<'tvb, ()>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..N {
            size += <T as Dissect<'tvb, ()>>::add_to_tree(args, fields);
        }
        size
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..N {
            size += <T as Dissect<'tvb, ()>>::size(args, fields);
        }
        size
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<()>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

impl<'tvb, T, const N: usize> Dissect<'tvb, [u8]> for [T; N]
where
    T: Dissect<'tvb, [u8]>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..N {
            size += <T as Dissect<'tvb, [u8]>>::add_to_tree(args, fields);
        }
        size
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        let mut size = 0;
        for _ in 0..N {
            size += <T as Dissect<'tvb, [u8]>>::size(args, fields);
        }
        size
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<[u8]>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

impl<'tvb, T> Dissect<'tvb, ()> for &[T]
where
    T: Dissect<'tvb, ()>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<T> as Dissect<'tvb, ()>>::add_to_tree(args, fields)
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<T> as Dissect<()>>::size(args, fields)
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<()>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

impl<'tvb, T> Dissect<'tvb, [u8]> for &[T]
where
    T: Dissect<'tvb, [u8]>,
{
    type Emit = ();

    fn add_to_tree(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<T> as Dissect<'tvb, [u8]>>::add_to_tree(args, fields)
    }

    fn size(args: &DissectorArgs<'_, 'tvb>, fields: &mut FieldsStore<'tvb>) -> usize {
        <Vec<T> as Dissect<[u8]>>::size(args, fields)
    }

    fn register(args: &RegisterArgs, ws_indices: &mut WsIndices) {
        <T as Dissect<[u8]>>::register(args, ws_indices);
    }

    fn emit(_args: &DissectorArgs) -> Self::Emit {}
}

#[cfg(test)]
mod test_with_dummy_proto {
    use super::*;
    use std::sync::Once;

    macro_rules! cstr {
        ($x:expr) => {
            concat!($x, '\0').as_ptr() as *const std::ffi::c_char
        };
    }

    static INIT_DUMMY_PROTOCOL: Once = Once::new();
    static mut DUMMY_PROTOCOL_ID: c_int = -1;

    /// Registers a dummy protocol with wireshark.
    fn init_proto() {
        INIT_DUMMY_PROTOCOL.call_once(|| unsafe {
            DUMMY_PROTOCOL_ID = epan_sys::proto_register_protocol(
                cstr!("Dummy Protocol"),
                cstr!("Dummy Protocol"),
                cstr!("dummy_proto"),
            );
            assert_ne!(DUMMY_PROTOCOL_ID, -1);
        });
    }

    fn get_dummy_proto_reg_args() -> RegisterArgs<'static> {
        RegisterArgs {
            proto_id: unsafe { DUMMY_PROTOCOL_ID },
            name: cstr!("Dummy Protocol"),
            prefix: "dummy_proto",
            blurb: std::ptr::null(),
            ws_type: None,
            ws_display: None,
        }
    }

    /// Checks the a hf index is not -1, and that when queried, it returns a non-null pointer to a
    /// header_field_info struct.
    macro_rules! assert_hf_ok {
		($idx:expr $(,)?) => {
			assert_ne!($idx, -1);
			assert_ne!(unsafe { epan_sys::proto_registrar_get_nth($idx as _) }, std::ptr::null_mut());
		};
		($idx:expr, $($idxs:expr),+ $(,)?) => {
			assert_hf_ok!($idx);
			assert_hf_ok!($($idxs),+);
		}
	}

    #[test]
    fn can_insert_hf() {
        init_proto();
        let args = get_dummy_proto_reg_args();

        let mut hf_indices = HfIndices::default();
        let idx = hf_indices.get_or_create_text_node(&args);

        assert_hf_ok!(idx);
    }

    #[test]
    fn can_insert_ett() {
        init_proto();
        let args = get_dummy_proto_reg_args();

        let mut ett_indices = EttIndices::default();
        let idx = ett_indices.get_or_create_ett(&args);

        assert_ne!(idx, -1);
    }

    #[test]
    fn can_insert_multiple_hfs() {
        init_proto();
        let mut args = get_dummy_proto_reg_args();

        let mut hf_indices = HfIndices::default();
        let idx1 = hf_indices.get_or_create_text_node(&args);
        args.prefix = "dummy_proto2";
        let idx2 = hf_indices.get_or_create_text_node(&args);

        assert_ne!(idx1, idx2);
        assert_hf_ok!(idx1, idx2);
    }

    #[test]
    fn can_insert_multiple_etts() {
        init_proto();
        let mut args = get_dummy_proto_reg_args();

        let mut ett_indices = EttIndices::default();
        let idx1 = ett_indices.get_or_create_ett(&args);
        args.prefix = "dummy_proto2";
        let idx2 = ett_indices.get_or_create_ett(&args);

        assert_ne!(idx1, idx2);
    }

    #[test]
    fn hf_indices_are_idempotent() {
        init_proto();
        let args = get_dummy_proto_reg_args();

        let mut hf_indices = HfIndices::default();

        let idx1 = hf_indices.get_or_create_text_node(&args);
        let idx2 = hf_indices.get_or_create_text_node(&args);

        assert_eq!(idx1, idx2);
        assert_hf_ok!(idx1);
    }

    #[test]
    fn ett_indices_are_idempotent() {
        init_proto();
        let args = get_dummy_proto_reg_args();

        let mut ett_indices = EttIndices::default();

        let idx1 = ett_indices.get_or_create_ett(&args);
        let idx2 = ett_indices.get_or_create_ett(&args);

        assert_eq!(idx1, idx2);
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
