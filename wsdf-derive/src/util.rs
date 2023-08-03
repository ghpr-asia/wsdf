use std::fmt::Display;

use once_cell::sync::Lazy;
use quote::{format_ident, quote};
use regex::{Captures, Regex};
use syn::{parse_quote, punctuated::Punctuated, spanned::Spanned};

pub(crate) fn make_err<T>(tok: &impl Spanned, msg: &str) -> Result<T, syn::Error> {
    Err(syn::Error::new(tok.span(), msg))
}

/// Extracts a literal value out of some `name = value` meta item.
///
/// # Example
///
/// ```ignore
/// extract_lit!(nv, Bool, "expected a boolean literal")?;
/// ```
macro_rules! get_lit {
    ($($expr:ident).+, $lit_ty:ident, $err:literal $(,)?) => {
        match $($expr).+ {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::$lit_ty(ref x),
                ..
            }) => Ok(x),
            _ => Err(syn::Error::new($($expr).+.span(), $err)),
        }
    };
}

pub(crate) fn get_lit_str(expr: &syn::Expr) -> syn::Result<&syn::LitStr> {
    get_lit!(expr, Str, "expected a string literal")
}

pub(crate) fn get_lit_int(expr: &syn::Expr) -> syn::Result<&syn::LitInt> {
    get_lit!(expr, Int, "expected an integer literal")
}

pub(crate) fn get_lit_bool(expr: &syn::Expr) -> syn::Result<&syn::LitBool> {
    get_lit!(expr, Bool, "expected a boolean literal")
}

pub(crate) fn parse_strings<T: syn::parse::Parse>(expr: &syn::Expr) -> syn::Result<Vec<T>> {
    let xs = unpack_expr(expr);
    let mut ret = Vec::with_capacity(xs.len());
    for x in xs {
        let s = get_lit_str(x)?;
        ret.push(syn::parse_str::<T>(&s.value())?);
    }
    Ok(ret)
}

// Trick from https://stackoverflow.com/a/59619245
#[derive(Debug, Clone, Copy)]
pub(crate) struct IdentHelper<'a>(pub(crate) &'a str);

impl<'a> From<&'a str> for IdentHelper<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}

impl From<IdentHelper<'_>> for proc_macro2::Ident {
    fn from(val: IdentHelper<'_>) -> Self {
        format_ident!("{}", val.0)
    }
}

impl quote::ToTokens for IdentHelper<'_> {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        Into::<proc_macro2::Ident>::into(*self).to_tokens(tokens);
    }
}

pub(crate) const WSDF_PARENT_NODE: IdentHelper = IdentHelper("__wsdf_parent");
pub(crate) const WSDF_OFFSET: IdentHelper = IdentHelper("__wsdf_offset");
pub(crate) const WSDF_DISSECTOR_TABLE: IdentHelper = IdentHelper("__wsdf_dissector_table");
pub(crate) const WSDF_PROTO_ID: IdentHelper = IdentHelper("__wsdf_proto_id");
pub(crate) const WSDF_TVB: IdentHelper = IdentHelper("__wsdf_tvb");
pub(crate) const WSDF_START: IdentHelper = IdentHelper("__wsdf_start");
pub(crate) const WSDF_PINFO: IdentHelper = IdentHelper("__wsdf_pinfo");
pub(crate) const WSDF_PREFIX: IdentHelper = IdentHelper("__wsdf_prefix");
pub(crate) const WSDF_PREFIX_NEXT: IdentHelper = IdentHelper("__wsdf_prefix_next");
pub(crate) const WSDF_DISPATCH: IdentHelper = IdentHelper("__wsdf_dispatch");
pub(crate) const WSDF_SUBTREE_LABEL: IdentHelper = IdentHelper("__wsdf_subtree_label");
pub(crate) const WSDF_TVB_BUF: IdentHelper = IdentHelper("__wsdf_tvb_buf");
pub(crate) const WSDF_HFS: IdentHelper = IdentHelper("__wsdf_hfs");
pub(crate) const WSDF_FIELD_IDENT: IdentHelper = IdentHelper("__wsdf_field_ident");
pub(crate) const WSDF_FIELD_BLURB: IdentHelper = IdentHelper("__wsdf_field_blurb");
pub(crate) const WSDF_PROTO_TREE_ROOT: IdentHelper = IdentHelper("__wsdf_proto_tree_root");
pub(crate) const WSDF_FIELDS_STORE: IdentHelper = IdentHelper("__wsdf_fields_store");
pub(crate) const WSDF_TAP_CTX: IdentHelper = IdentHelper("__wsdf_tap_ctx");

/// Unpacks an array or tuple expression into its individual elements. Otherwise, return the
/// original expression.
pub(crate) fn unpack_expr(expr: &syn::Expr) -> Vec<&syn::Expr> {
    match expr {
        syn::Expr::Array(xs) => xs.elems.iter().collect(),
        syn::Expr::Tuple(xs) => xs.elems.iter().collect(),
        _ => vec![expr],
    }
}

#[cfg(test)]
mod test_unpack_expr {
    use super::*;

    #[test]
    fn can_unpack_array_literals() {
        let x: syn::Expr = parse_quote! { 1 };
        let y: syn::Expr = parse_quote! { 2 };
        let xs: syn::Expr = parse_quote! { [#x, #y] };
        assert_eq!(unpack_expr(&xs), vec![&x, &y]);
    }

    #[test]
    fn can_unpack_tuple_literals() {
        let x: syn::Expr = parse_quote! { 1 };
        let y: syn::Expr = parse_quote! { "foo" };
        let xs: syn::Expr = parse_quote! { (#x, #y) };
        assert_eq!(unpack_expr(&xs), vec![&x, &y]);
    }

    #[test]
    fn unpacks_single_expr() {
        let x: syn::Expr = parse_quote! { 1 };
        assert_eq!(unpack_expr(&x), vec![&x]);
    }
}

/// Produces a token stream for a null-terminated string expression. The resultant expression can
/// be used anywhere in a quote macro.
macro_rules! cstr {
    ($x:ident) => {
        syn::parse_quote! { concat!(#$x, '\0').as_ptr() as *const std::ffi::c_char }
    };
    ($x:expr) => {
        syn::parse_quote! { concat!($x, '\0').as_ptr() as *const std::ffi::c_char }
    };
}

pub(crate) use cstr; // hack to "export" cstr macro

/// Just wraps a String, such that when we `Display` or `ToString` it, the appropriate enum prefix in
/// the bindgen code (field_display_e) is added.
///
/// Thus, it is purely for formatting and convenience purposes, and does not perform any validation
/// on whether the string reflects an actual value from the epan library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldDisplay(String);

impl FieldDisplay {
    pub(crate) fn new(raw: &str) -> Self {
        // Some of these values have a prefix, and some don't.
        match raw {
            "BASE_RANGE_STRING"
            | "BASE_EXT_STRING"
            | "BASE_VAL64_STRING"
            | "BASE_ALLOW_ZERO"
            | "BASE_UNIT_STRING"
            | "BASE_NO_DISPLAY_VALUE"
            | "BASE_PROTOCOL_INFO"
            | "BASE_SPECIAL_VALS"
            | "BASE_SHOW_ASCII_PRINTABLE"
            | "BASE_SHOW_UTF_8_PRINTABLE" => Self(raw.to_string()),
            _ => Self(format!("field_display_e_{raw}")),
        }
    }
}

impl Display for FieldDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl quote::IdentFragment for FieldDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self}")
    }
}

pub(crate) fn format_ws_type(typ: &str) -> syn::Path {
    let unqualified = format_ident!("ftenum_{}", typ);
    parse_quote! { wsdf::epan_sys::#unqualified }
}

pub(crate) fn format_ws_enc(enc: &str) -> syn::Path {
    let unqualified = format_ident!("{}", enc);
    parse_quote! { wsdf::epan_sys::#unqualified }
}

pub(crate) trait CaseConvert {
    fn to_wsdf_snake_case(&self) -> String;
    fn to_wsdf_upper_case(&self) -> String;
    fn to_wsdf_title_case(&self) -> String;
}

impl<T: ToString> CaseConvert for T {
    fn to_wsdf_snake_case(&self) -> String {
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(([a-z])?([A-Z]))|(\s+(\w))")
                .expect("regexp for Camel/Pascal case should be valid")
        });

        RE.replace_all(&self.to_string(), |captures: &Captures| {
            if let Some(c) = captures.get(5) {
                return format!("_{}", c.as_str().to_ascii_lowercase());
            }
            debug_assert!(captures.get(1).is_some());
            debug_assert!(captures.get(3).is_some());
            let x = captures[3].to_ascii_lowercase();
            match captures.get(2) {
                None => x,
                Some(c) => format!("{}_{}", c.as_str(), x),
            }
        })
        .to_string()
    }

    fn to_wsdf_upper_case(&self) -> String {
        self.to_wsdf_title_case().to_uppercase()
    }

    fn to_wsdf_title_case(&self) -> String {
        let s = self.to_wsdf_snake_case();
        let words = s.split('_').filter(|word| !word.trim().is_empty());
        let mut ret = String::new();
        for word in words {
            let mut cs = word.chars();
            let new_word = match cs.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().chain(cs).collect(),
            };
            ret.push_str(&new_word);
            ret.push(' ');
        }
        ret.trim().to_string()
    }
}

#[cfg(test)]
mod test_case_convert {
    use super::CaseConvert;

    #[test]
    fn to_wsdf_snake_case_works() {
        let tests = [
            ("FooBar", "foo_bar"),
            ("foo_bar", "foo_bar"),
            ("fooBar", "foo_bar"),
            ("_FooBar", "_foo_bar"),
            ("FooBar_", "foo_bar_"),
            ("_FooBar_", "_foo_bar_"),
            ("__foo_bar", "__foo_bar"), // it should preserve any extra leading or trailing underscores
            ("__foo__bar", "__foo__bar"),
            ("foo bar", "foo_bar"),
            ("Foo Bar", "foo_bar"),
        ];

        for (tt, want) in tests {
            assert_eq!(tt.to_wsdf_snake_case(), want);
        }
    }

    #[test]
    fn to_wsdf_title_case_works() {
        let tests = [
            ("FooBar", "Foo Bar"),
            ("foo_bar", "Foo Bar"),
            ("fooBar", "Foo Bar"),
            ("foo_bar_", "Foo Bar"),
            ("_foo_bar", "Foo Bar"),
            ("_foo_bar_", "Foo Bar"),
            ("__foo_bar__", "Foo Bar"),
        ];

        for (tt, want) in tests {
            assert_eq!(tt.to_wsdf_title_case(), want);
        }
    }

    #[test]
    fn to_wsdf_upper_case_works() {
        let tests = [
            ("FooBar", "FOO BAR"),
            ("foo_bar", "FOO BAR"),
            ("fooBar", "FOO BAR"),
            ("foo_bar_", "FOO BAR"),
            ("_foo_bar", "FOO BAR"),
            ("_foo_bar_", "FOO BAR"),
            ("__foo_bar__", "FOO BAR"),
        ];

        for (tt, want) in tests {
            assert_eq!(tt.to_wsdf_upper_case(), want);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct _DissectionParams;
pub(crate) const DISSECTION_PARAMS: _DissectionParams = _DissectionParams;

impl From<_DissectionParams> for Punctuated<syn::FnArg, syn::Token![,]> {
    fn from(_val: _DissectionParams) -> Self {
        // Note that we have some 'a lifetimes here. Thus we'll have to remember to declare the 'a
        // anywhere this is used.
        parse_quote! {
            #WSDF_START: std::ffi::c_int,
            #WSDF_TVB: *mut wsdf::epan_sys::tvbuff,
            #WSDF_PARENT_NODE: *mut wsdf::epan_sys::_proto_node,
            #WSDF_PREFIX: &str,
            #WSDF_DISPATCH: wsdf::VariantDispatch,
            #WSDF_SUBTREE_LABEL: wsdf::SubtreeLabel,
            #WSDF_TVB_BUF: &'a [u8],
            #WSDF_PINFO: *mut wsdf::epan_sys::_packet_info,
            #WSDF_PROTO_TREE_ROOT: *mut wsdf::epan_sys::_proto_node,
            #WSDF_FIELDS_STORE: &mut wsdf::FieldsStore<'a>,
        }
    }
}

impl quote::ToTokens for _DissectionParams {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        Into::<Punctuated<syn::FnArg, syn::Token![,]>>::into(*self).to_tokens(tokens);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct _RegistrationParams;
pub(crate) const REGISTRATION_PARAMS: _RegistrationParams = _RegistrationParams;

impl From<_RegistrationParams> for Punctuated<syn::FnArg, syn::Token![,]> {
    fn from(_val: _RegistrationParams) -> Self {
        parse_quote! {
            #WSDF_PREFIX: &str,
            #WSDF_PROTO_ID: std::ffi::c_int,
            #WSDF_FIELD_IDENT: wsdf::FieldIdent,
            #WSDF_FIELD_BLURB: wsdf::FieldBlurb,
        }
    }
}

impl quote::ToTokens for _RegistrationParams {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        Into::<Punctuated<syn::FnArg, syn::Token![,]>>::into(*self).to_tokens(tokens);
    }
}

/// A helper trait to "collapse" vectors of Expr, Stmt, etc. into a single `TokenStream`.
pub(crate) trait StreamTokens {
    fn streamify(self) -> proc_macro2::TokenStream;
}

impl<T, S> StreamTokens for T
where
    T: IntoIterator<Item = S>,
    S: quote::ToTokens,
{
    fn streamify(self) -> proc_macro2::TokenStream {
        let it = self.into_iter();
        quote! {
            #(#it)*
        }
    }
}
