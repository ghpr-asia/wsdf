//! This crate provides the derive macros for [wsdf](http://docs.rs/wsdf), along with some helpers.

use model::Enum;
use proc_macro::TokenStream;

use quote::{format_ident, quote, ToTokens};
use syn::parse::{Parse, ParseStream};
use syn::parse_quote;
use syn::punctuated::Punctuated;

mod attributes;
mod model;
mod types;
mod util;

use crate::attributes::*;
use crate::model::{DataRoot, StructInnards};
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
            let new_struct_defs = data.variants.iter().map(|variant| -> syn::ItemStruct {
                let newtype_ident = format_ident!("__{}", variant.ident);
                let fields = &variant.fields;

                match fields {
                    syn::Fields::Named(_) => parse_quote! {
                        #[derive(wsdf::Dissect)]
                        struct #newtype_ident #fields
                    },
                    syn::Fields::Unnamed(_) => parse_quote! {
                        #[derive(wsdf::Dissect)]
                        struct #newtype_ident #fields;
                    },
                    syn::Fields::Unit => parse_quote! {
                        #[derive(wsdf::Dissect)]
                        struct #newtype_ident;
                    },
                }
            });

            let actual_impl = derive_dissect_impl_enum(&input.ident, &data.variants);

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

fn derive_dissect_impl_enum(
    ident: &syn::Ident,
    variants: &Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::ItemImpl {
    let enum_data = Enum::new(ident, variants);

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
