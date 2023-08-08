//! This crate provides the derive macros for [wsdf](http://docs.rs/wsdf), along with some helpers.

use proc_macro::TokenStream;

use quote::{format_ident, quote, ToTokens};
use syn::parse::{Parse, ParseStream};
use syn::parse_quote;

mod attributes;
mod model;
mod types;
mod util;

use crate::attributes::*;
use crate::model::{DataRoot, Enum, StructInnards};
use crate::util::*;

#[derive(Debug)]
struct VersionMacroInput {
    plugin_ver: syn::LitStr,
    ws_major_ver: syn::LitInt,
    ws_minor_ver: syn::LitInt,
}

impl Parse for VersionMacroInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let plugin_ver = Parse::parse(input)?;
        <syn::Token![,]>::parse(input)?;
        let ws_major_ver = Parse::parse(input)?;
        <syn::Token![,]>::parse(input)?;
        let ws_minor_ver = Parse::parse(input)?;
        Ok(VersionMacroInput {
            plugin_ver,
            ws_major_ver,
            ws_minor_ver,
        })
    }
}

/// Declares the plugin version and supported Wireshark version.
///
/// # Example
///
/// The following usage declares a plugin version of 0.0.1, built for wireshark version 4.0.x.
///
/// ```
/// use wsdf_derive::version;
/// version!("0.0.1", 4, 0);
/// ```
#[proc_macro]
pub fn version(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as VersionMacroInput);

    let nr_chars = input.plugin_ver.value().len() + 1;
    let mut ver_str = Vec::with_capacity(nr_chars);
    for ch in input.plugin_ver.value().as_bytes() {
        ver_str.push(*ch as i8);
    }
    ver_str.push(0); // pad a null byte

    let ws_major_ver = input.ws_major_ver;
    let ws_minor_ver = input.ws_minor_ver;

    let version_info = quote! {
        #[no_mangle]
        #[used]
        static plugin_version: [std::ffi::c_char; #nr_chars] = [#(#ver_str),*];
        #[no_mangle]
        #[used]
        static plugin_want_major: std::ffi::c_int = #ws_major_ver;
        #[no_mangle]
        #[used]
        static plugin_want_minor: std::ffi::c_int = #ws_minor_ver;
    };

    version_info.into()
}

/// Marks a struct as the protocol root.
#[proc_macro_derive(Protocol, attributes(wsdf))]
pub fn derive_protocol(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let ret = derive_protocol_impl(&input).unwrap_or_else(|e| e.to_compile_error());
    ret.into()
}

fn derive_protocol_impl(input: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    match &input.data {
        syn::Data::Enum(_) | syn::Data::Union(_) => {
            return make_err(input, "only structs can derive Protocol");
        }
        syn::Data::Struct(_) => (),
    }

    let root = DataRoot::from_input(input, true)?;
    let proto_opts = init_options::<ProtocolOptions>(&input.attrs)?;

    if proto_opts.decode_from.is_empty() {
        return make_err(
            &input.ident,
            "expected some way of registering with dissector table",
        );
    }

    let add_dissector = proto_opts.decode_from.iter().map(DecodeFrom::to_tokens);

    let upper_cased = input.ident.to_wsdf_upper_case();
    let snake_cased = input.ident.to_wsdf_snake_case();

    let proto_desc = proto_opts.proto_desc.as_ref().unwrap_or(&upper_cased);
    let proto_name = proto_opts.proto_name.as_ref().unwrap_or(&upper_cased);
    let proto_filter = proto_opts.proto_filter.as_ref().unwrap_or(&snake_cased);

    let proto_desc_cstr: syn::Expr = cstr!(proto_desc);
    let proto_name_cstr: syn::Expr = cstr!(proto_name);
    let proto_filter_cstr: syn::Expr = cstr!(proto_filter);

    let dissect_fn = root.dissection_fn();
    let register_fn = root.registration_fn();

    let input_ident = &input.ident;

    let plugin_register = quote! {
        #[no_mangle]
        extern "C" fn plugin_register() {
            static mut plug: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
                register_protoinfo: None,
                register_handoff: None,
            };
            // SAFETY: this code is only called once in a single thread when wireshark starts
            unsafe {
                plug.register_protoinfo =
                    std::option::Option::Some(<#input_ident as wsdf::Protocol>::proto_register);
                plug.register_handoff =
                    std::option::Option::Some(<#input_ident as wsdf::Protocol>::proto_reg_handoff);
                wsdf::epan_sys::proto_register_plugin(&plug);
            }
        }
    };

    let init_rust_owned_tvb_buf = init_tvb_buf();

    let main_dissect_fn = quote! {
        unsafe extern "C" fn dissect_main(
            #WSDF_TVB: *mut wsdf::epan_sys::tvbuff,
            #WSDF_PINFO: *mut wsdf::epan_sys::_packet_info,
            #WSDF_PROTO_TREE_ROOT: *mut wsdf::epan_sys::_proto_node,
            __wsdf_data: *mut std::ffi::c_void, // unused
        ) -> std::ffi::c_int {
            wsdf::epan_sys::col_set_str(
                (*#WSDF_PINFO).cinfo,
                wsdf::epan_sys::COL_PROTOCOL as std::ffi::c_int,
                #proto_desc_cstr,
            );
            wsdf::epan_sys::col_clear(
                (*#WSDF_PINFO).cinfo,
                wsdf::epan_sys::COL_INFO as std::ffi::c_int,
            );

            #init_rust_owned_tvb_buf

            // Initialize a context to keep fields.
            let mut #WSDF_FIELDS_STORE = wsdf::FieldsStore::default();

            <#input_ident as wsdf::ProtocolField>::dissect(
                0,
                #WSDF_TVB,
                #WSDF_PROTO_TREE_ROOT,
                #proto_filter,
                wsdf::VariantDispatch::None,
                wsdf::SubtreeLabel::new(#proto_name_cstr),
                &#WSDF_TVB_BUF,
                #WSDF_PINFO,
                #WSDF_PROTO_TREE_ROOT,
                &mut #WSDF_FIELDS_STORE,
            )
        }
    };

    let protoinfo_fn = quote! {
        extern "C" fn proto_register() {
            let proto_id = unsafe {
                wsdf::epan_sys::proto_register_protocol(
                    #proto_desc_cstr,
                    #proto_name_cstr,
                    #proto_filter_cstr,
                )
            };
            <#input_ident as wsdf::ProtocolField>::register(
                #proto_filter,
                proto_id,
                wsdf::FieldIdent::null(),
                wsdf::FieldBlurb::null(),
            );
        }
    };

    let handoff_fn = quote! {
        extern "C" fn proto_reg_handoff() {
            unsafe {
                let handle = wsdf::epan_sys::create_dissector_handle(
                    std::option::Option::Some(<#input_ident as wsdf::Protocol>::dissect_main),
                    *<#input_ident as wsdf::ProtocolField>::proto_id(),
                );
                #(#add_dissector)*
            }
        }
    };

    let static_int_getters = static_int_getters();
    let static_maps = static_map_fns();

    let ret = quote! {
        #plugin_register

        impl wsdf::Protocol for #input_ident {
            #main_dissect_fn
            #protoinfo_fn
            #handoff_fn
        }

        impl wsdf::ProtocolField for #input_ident {
            #dissect_fn
            #register_fn

            #static_int_getters
            #static_maps
        }
    };

    Ok(ret)
}

/// Creates the code to initialize a Rust owned TVB slice.
fn init_tvb_buf() -> proc_macro2::TokenStream {
    const WSDF_TVB_BUF_SIZE: IdentHelper = IdentHelper("__wsdf_tvb_buf_size");
    quote! {
        let #WSDF_TVB_BUF_SIZE = unsafe {
            wsdf::epan_sys::tvb_reported_length(#WSDF_TVB) as usize
        };
        let mut #WSDF_TVB_BUF = Vec::new();
        #WSDF_TVB_BUF.resize(#WSDF_TVB_BUF_SIZE, 0);
        unsafe {
            wsdf::epan_sys::tvb_memcpy(
                #WSDF_TVB,
                #WSDF_TVB_BUF.as_mut_ptr() as *mut std::ffi::c_void,
                0,
                #WSDF_TVB_BUF_SIZE,
            );
        }

    }
}

/// Registers a type to be used as a field within the main `#[derive(Protocol)]` type.
#[proc_macro_derive(ProtocolField, attributes(wsdf))]
pub fn derive_protocol_field(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let ret = derive_protocol_field_impl(&input).unwrap_or_else(|e| e.to_compile_error());
    ret.into()
}

fn derive_protocol_field_impl(input: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let root = DataRoot::from_input(input, false)?;

    let input_ident = &input.ident;
    let dissect_fn = root.dissection_fn();
    let register_fn = root.registration_fn();

    let static_int_getters = static_int_getters();
    let static_maps = static_map_fns();

    let ret = quote! {
        impl wsdf::ProtocolField for #input_ident {
            #dissect_fn
            #register_fn

            #static_int_getters
            #static_maps
        }
    };

    Ok(ret)
}

fn static_int_getters() -> proc_macro2::TokenStream {
    quote! {
        fn ett() -> std::ffi::c_int {
            static mut ETT: std::ffi::c_int = -1;

            // The ETT will be initialized once the first time we all it.
            static INIT_ETT: std::sync::Once = std::sync::Once::new();
            INIT_ETT.call_once(|| unsafe {
                debug_assert_eq!(ETT, -1);
                wsdf::epan_sys::proto_register_subtree_array(
                    [unsafe { &mut ETT as *mut _ }].as_mut_ptr(),
                    1
                );
            });

            unsafe { ETT }
        }

        fn proto_id() -> &'static mut std::ffi::c_int {
            static mut PROTO_ID: std::ffi::c_int = -1;
            unsafe { &mut PROTO_ID }
        }
    }
}

fn static_map_fns() -> proc_macro2::TokenStream {
    quote! {
        fn subdissector_map(op: wsdf::SubdissectorMapOp) -> std::option::Option<wsdf::epan_sys::dissector_table_t> {
            thread_local! {
                static SUBDISSECTORS: wsdf::SubdissectorMap = wsdf::SubdissectorMap::default();
            }
            SUBDISSECTORS.with(|subdissectors| subdissectors.accept(op))
        }

        fn hf_map(op: wsdf::HfMapOp) -> std::option::Option<std::ffi::c_int> {
            thread_local! {
                static HFS: wsdf::HfMap = wsdf::HfMap::default();
            }
            HFS.with(|hfs| hfs.accept(op))
        }
    }
}

/// A helper macro to generate an "index" for an enum.
#[proc_macro_derive(Dispatch)]
pub fn derive_dispatch(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let data_enum = match input.data {
        syn::Data::Enum(data_enum) => data_enum,
        _ => {
            return syn::Error::new(input.ident.span(), "expected enum")
                .to_compile_error()
                .into()
        }
    };

    let new_type_ident = format_ident!("{}Dispatch", input.ident);
    let new_variants = data_enum.variants.iter().map(|variant| &variant.ident);
    let dispatch_variant_usize = new_variants
        .clone()
        .enumerate()
        .map(|(idx, variant_ident)| {
            quote! {
                #new_type_ident::#variant_ident => #idx,
            }
        });

    quote! {
        enum #new_type_ident {
            #(#new_variants),*
        }
        impl std::convert::From<#new_type_ident> for usize {
            fn from(value: #new_type_ident) -> Self {
                match value {
                    #(#dispatch_variant_usize)*
                }
            }
        }
    }
    .into()
}

/// Derive macro for the `Dissect` trait.
#[proc_macro_derive(Dissect, attributes(wsdf))]
pub fn derive_dissect(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let ret = derive_dissect_impl(&input).unwrap_or_else(|e| e.to_compile_error());
    ret.into()
}

fn derive_dissect_impl(input: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let dissect_options = init_options::<ProtocolFieldOptions>(&input.attrs)?;
    match &input.data {
        syn::Data::Struct(data) => {
            let struct_info = StructInnards::from_fields(&data.fields)?;
            let ret = derive_dissect_impl_struct(&input.ident, &dissect_options, &struct_info);
            Ok(ret.to_token_stream())
        }
        syn::Data::Enum(data) => {
            let mut new_struct_defs: Vec<syn::ItemStruct> = Vec::with_capacity(data.variants.len());
            for variant in &data.variants {
                // We'll cheat for enums. For each variant, we create a new struct, and then derive
                // Dissect on that struct.

                let pre_dissect = filter_for_meta_value(&variant.attrs, META_PRE_DISSECT)?;
                let pre_dissect: syn::Attribute = parse_quote! {
                    #[wsdf(pre_dissect = [#(#pre_dissect),*])]
                };
                let post_dissect = filter_for_meta_value(&variant.attrs, META_POST_DISSECT)?;
                let post_dissect: syn::Attribute = parse_quote! {
                    #[wsdf(post_dissect = [#(#post_dissect),*])]
                };

                let newtype_ident = format_ident!("__{}", variant.ident);
                let fields = &variant.fields;

                let struct_def: syn::ItemStruct = match fields {
                    syn::Fields::Named(_) => parse_quote! {
                        struct #newtype_ident #fields
                    },
                    syn::Fields::Unnamed(_) => parse_quote! {
                        struct #newtype_ident #fields;
                    },
                    syn::Fields::Unit => parse_quote! {
                        struct #newtype_ident;
                    },
                };
                let struct_def = parse_quote! {
                    #[derive(wsdf::Dissect)]
                    #pre_dissect
                    #post_dissect
                    #struct_def
                };
                new_struct_defs.push(struct_def);
            }

            let enum_data = Enum::new(&input.ident, &data.variants)?;
            // And of course the actual implementation of Dissect for the enum type. It will call
            // into functions from the dummy structs we created.
            let actual_impl = derive_dissect_impl_enum(&enum_data);

            Ok(quote! {
                #(#new_struct_defs)*
                #actual_impl
            })
        }
        syn::Data::Union(data) => make_err(
            &data.union_token,
            "#[derive(Dissect)] cannot be used on unions",
        ),
    }
}

fn derive_dissect_impl_struct(
    ident: &syn::Ident,
    dissect_options: &ProtocolFieldOptions,
    struct_info: &StructInnards,
) -> syn::ItemImpl {
    let fn_add_to_tree = struct_info.add_to_tree_fn(dissect_options);
    let fn_size = struct_info.size_fn();
    let fn_register = struct_info.register_fn();

    parse_quote! {
        impl<'tvb> wsdf::Dissect<'tvb, ()> for #ident {
            type Emit = ();
            #fn_add_to_tree
            #fn_size
            #fn_register
            fn emit(_args: &wsdf::DissectorArgs) {}
        }
    }
}

fn derive_dissect_impl_enum(enum_data: &Enum) -> syn::ItemImpl {
    let ident = enum_data.ident();
    let fn_add_to_tree = enum_data.add_to_tree_fn();
    let fn_size = enum_data.size_fn();
    let fn_register = enum_data.register_fn();

    parse_quote! {
        impl<'tvb> wsdf::Dissect<'tvb, ()> for #ident {
            type Emit = ();
            #fn_add_to_tree
            #fn_size
            #fn_register
            fn emit(args: &wsdf::DissectorArgs<'_, 'tvb>) {}
        }
    }
}

/// A list of types to be registered as protocols.
struct SelectedProtocols(Vec<syn::Type>);

impl Parse for SelectedProtocols {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let roots: Vec<syn::Type> = input
            .parse_terminated(syn::Type::parse, syn::Token![,])?
            .into_iter()
            .collect();
        Ok(SelectedProtocols(roots))
    }
}

/// Selects some types to be registered as protocols.
///
/// Also declares some globals and sets up the plugin entry point which Wireshark will call.
///
/// ```rust
/// use wsdf::{protocol, Proto, Dissect};
///
/// protocol!(Udp, UdpLite); // multiple protocols per dynamic library!
///
/// #[derive(Proto, Dissect)]
/// #[wsdf(decode_from = [("ip.proto", 17)])]
/// struct Udp { /* UDP fields */ }
///
/// #[derive(Proto, Dissect)]
/// #[wsdf(decode_from = [("ip.proto", 136)])]
/// struct UdpLite { /* UDP-lite fields */ }
/// ```
#[proc_macro]
pub fn protocol(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as SelectedProtocols);

    let register_protos = input
        .0
        .iter()
        .enumerate()
        .flat_map(|(i, ty)| -> Vec<syn::Stmt> {
            // We'll call the `proto_register_plugin` function once for each protocol.
            let plug = format_ident!("PLUG_{i}");
            parse_quote! {
                static mut #plug: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
                    register_protoinfo: None,
                    register_handoff: None,
                };
                unsafe {
                    #plug.register_protoinfo =
                        std::option::Option::Some(<#ty as wsdf::Proto>::register_protoinfo);
                    #plug.register_handoff =
                        std::option::Option::Some(<#ty as wsdf::Proto>::register_handoff);
                    wsdf::epan_sys::proto_register_plugin(&#plug);
                }
            }
        });

    quote! {
        // We use three global maps to keep track of "static" values. In C dissectors, these would
        // literally be static quantities defined somewhere in the code.
        //
        // There might be a better way to inject these into our dissection and registration
        // routines, but this should work perfectly fine, even if it is ugly.
        thread_local! {
            static __WSDF_HF_INDICES: std::cell::RefCell<wsdf::HfIndices> = wsdf::HfIndices::default().into();
            static __WSDF_ETT_INDICES: std::cell::RefCell<wsdf::EttIndices> = wsdf::EttIndices::default().into();
            static __WSDF_DTABLES: std::cell::RefCell<wsdf::DissectorTables> = wsdf::DissectorTables::default().into();
        }

        // Wireshark will call this function to load our plugin.
        #[no_mangle]
        extern "C" fn plugin_register() {
            #(#register_protos)*
        }
    }.into()
}

/// Derive macro for the `Proto` trait.
#[proc_macro_derive(Proto, attributes(wsdf))]
pub fn derive_proto(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let ret = derive_proto_impl(&input)
        .map(|x| x.to_token_stream())
        .unwrap_or_else(|e| e.to_compile_error());
    ret.into()
}

fn derive_proto_impl(input: &syn::DeriveInput) -> syn::Result<syn::ItemImpl> {
    if !matches!(input.data, syn::Data::Struct { .. }) {
        return make_err(&input, "only structs can derive Proto");
    }

    let ident = &input.ident;

    let proto_opts = init_options::<ProtocolOptions>(&input.attrs)?;
    if proto_opts.decode_from.is_empty() {
        return make_err(&input.ident, "missing `decode_from` attribute");
    }

    let add_dissector = proto_opts.decode_from.iter().map(DecodeFrom::to_tokens);

    let upper_cased = input.ident.to_wsdf_upper_case();
    let snake_cased = input.ident.to_wsdf_snake_case();

    let proto_desc = proto_opts.proto_desc.as_ref().unwrap_or(&upper_cased);
    let proto_name = proto_opts.proto_name.as_ref().unwrap_or(&upper_cased);
    let proto_filter = proto_opts.proto_filter.as_ref().unwrap_or(&snake_cased);

    let proto_desc_cstr: syn::Expr = cstr!(proto_desc);
    let proto_name_cstr: syn::Expr = cstr!(proto_name);
    let proto_filter_cstr: syn::Expr = cstr!(proto_filter);

    Ok(parse_quote! {
        impl wsdf::Proto for #ident {
            #[allow(clippy::missing_safety_doc)]
            unsafe extern "C" fn dissect_main(
                tvb: *mut wsdf::epan_sys::tvbuff,
                pinfo: *mut wsdf::epan_sys::_packet_info,
                tree: *mut wsdf::epan_sys::_proto_node,
                data: *mut std::ffi::c_void,
            ) -> std::ffi::c_int {
                // Clear columns
                wsdf::epan_sys::col_set_str(
                    (*pinfo).cinfo,
                    wsdf::epan_sys::COL_PROTOCOL as std::ffi::c_int,
                    #proto_desc_cstr,
                );
                wsdf::epan_sys::col_clear(
                    (*pinfo).cinfo,
                    wsdf::epan_sys::COL_INFO as std::ffi::c_int,
                );

                // Initialize rust-owned TVB
                let tvb_len = unsafe {
                    wsdf::epan_sys::tvb_reported_length(tvb) as usize
                };
                let mut tvb_buf = Vec::new();
                tvb_buf.resize(tvb_len, 0);
                unsafe {
                    wsdf::epan_sys::tvb_memcpy(
                        tvb,
                        tvb_buf.as_mut_ptr() as *mut std::ffi::c_void,
                        0,
                        tvb_len,
                    );
                }

                __WSDF_HF_INDICES.with(|hf_indices|
                    __WSDF_ETT_INDICES.with(|etts|
                        __WSDF_DTABLES.with(|dtables| {
                            // create the packet-lifespan fields store
                            let mut fields = wsdf::FieldsStore::default();

                            let hf_indices = hf_indices.borrow();
                            let etts = etts.borrow();
                            let dtables = dtables.borrow();

                            let args = wsdf::DissectorArgs {
                                hf_indices: &hf_indices,
                                etts: &etts,
                                dtables: &dtables,
                                tvb,
                                pinfo,
                                proto_root: tree,
                                data: &tvb_buf,
                                prefix: #proto_filter,
                                prefix_local: #proto_filter,
                                offset: 0,
                                parent: tree,
                                variant: std::option::Option::None,
                                list_len: std::option::Option::None,
                                ws_enc: std::option::Option::None,
                            };

                            <#ident as Dissect<'_, ()>>::add_to_tree(&args, &mut fields) as _
                        })
                    )
                )
            }

            unsafe extern "C" fn register_protoinfo() {
                let proto_id = unsafe {
                    wsdf::epan_sys::proto_register_protocol(
                        #proto_desc_cstr,
                        #proto_name_cstr,
                        #proto_filter_cstr,
                    )
                };


                __WSDF_HF_INDICES.with(|hf_indices|
                    __WSDF_ETT_INDICES.with(|etts|
                        __WSDF_DTABLES.with(|dtables| {
                            let mut hf = hf_indices.borrow_mut();
                            let mut ett = etts.borrow_mut();
                            let mut dtable = dtables.borrow_mut();
                            let mut ws_indices = wsdf::WsIndices {
                                hf: &mut hf,
                                ett: &mut ett,
                                dtable: &mut dtable,
                            };

                            ws_indices.hf.insert(#proto_filter, proto_id);

                            let args = wsdf::RegisterArgs {
                                proto_id,
                                name: #proto_name_cstr,
                                prefix: #proto_filter,
                                blurb: std::ptr::null(),
                                ws_type: std::option::Option::None,
                                ws_display: std::option::Option::None,
                            };

                            <#ident as Dissect<'_, ()>>::register(&args, &mut ws_indices);
                        })
                    )
                );
            }

            unsafe extern "C" fn register_handoff() {
                __WSDF_HF_INDICES.with(|hf_indices| {
                    let hf_indices = hf_indices.borrow();
                    let proto_id = hf_indices.get(#proto_filter).unwrap();
                    unsafe {
                        let handle = wsdf::epan_sys::create_dissector_handle(
                            std::option::Option::Some(<#ident as wsdf::Proto>::dissect_main),
                            proto_id,
                        );
                        #(#add_dissector)*
                    }
                });
            }
        }
    })
}
