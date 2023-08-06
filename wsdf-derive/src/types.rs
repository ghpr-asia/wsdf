use quote::{format_ident, quote};
use syn::parse_quote;

use crate::{attributes::*, util::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DataType {
    /// Primitive types can be unambiguously mapped to a Wireshark type. The converse may not be
    /// true.
    Primitive(Primitive),
    /// Types which are not "primitive".
    Collection(Collection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Primitive {
    pub(crate) typ: PrimitiveType,

    pub(crate) hidden: bool,

    pub(crate) decode_with: Option<syn::Path>,
    taps: Vec<syn::Path>,

    /// Whether this field must be extracted and used later.
    ///
    /// Note that this cannot be determined from the field alone, since e.g. some fields may
    /// provide a length for some other field. In which case we would need to emit this field
    /// so that it can be used later.
    pub(crate) is_used_later: bool,
    should_save: bool,

    ws_type: Option<String>,
    ws_enc: Option<String>,
    ws_display: Option<FieldDisplayPair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Collection {
    pub(crate) typ: CollectionType,

    pub(crate) hidden: bool,
    taps: Vec<syn::Path>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrimitiveType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    /// Bytes, where the size will be known before we need to decode the field. Thus, its size
    /// might be either known statically (via a byte array), or its size might be determined by a
    /// prior field in the protocol.
    ByteArray {
        size: SizeHint,
        /// Bytes may be passed to a subdissector, instead of being used directly as a field in
        /// Wireshark's protocol tree.
        subdissector: Option<Subdissector>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionType {
    List {
        elem: Box<DataType>,
        len: SizeHint,
    },
    Struct {
        ident: syn::TypePath,
    },
    Enum {
        ident: syn::TypePath,
        /// A field is treated as an enum iff it is tagged with a dispatch attribute. This
        /// attribute should point at a previous field in the protocol whose value is used to
        /// determine the enum variant to use.
        dispatch: syn::Ident,
    },
    /// Bytes where the size is not known prior to decoding that field. For instance, the protocol
    /// might have fields adopting goofy TLV encoding schemes.
    Bytes {
        consume: ConsumeBytes,
    },
}

impl DataType {
    fn new_primitive(typ: PrimitiveType, opts: &FieldOptions) -> Self {
        Self::Primitive(Primitive::new(typ, opts))
    }

    fn new_collection(typ: CollectionType, opts: &FieldOptions) -> Self {
        Self::Collection(Collection::new(typ, opts))
    }

    fn default_ws_type(&self) -> &'static str {
        match self {
            DataType::Primitive(data) => data.default_ws_type(),
            DataType::Collection(data) => data.default_ws_type(),
        }
    }

    fn default_ws_display(&self) -> (&'static str, Option<&'static str>) {
        match self {
            DataType::Primitive(data) => data.default_ws_display(),
            DataType::Collection(data) => data.default_ws_display(),
        }
    }

    pub(crate) fn ws_type(&self) -> syn::Path {
        match self {
            DataType::Primitive(data) => data.ws_type(),
            DataType::Collection(data) => data.ws_type(),
        }
    }

    pub(crate) fn ws_display(&self) -> syn::Expr {
        match self {
            DataType::Primitive(data) => data.ws_display(),
            DataType::Collection(data) => data.ws_display(),
        }
    }

    /// Constructs a `DataType` from a `syn::Type`.
    pub(crate) fn from_syn_type(typ: &syn::Type, opts: &FieldOptions) -> syn::Result<Self> {
        let ret = match typ {
            syn::Type::Array(array) => Self::from_array_type(array, opts)?,
            syn::Type::Path(path) if path.path.segments.empty_or_trailing() => {
                // This shouldn't even be possible, but we'll handle it anyway.
                return make_err(path, "unexpected end of type");
            }
            syn::Type::Path(path) => {
                use PrimitiveType::*;

                let segment = path.path.segments.last().unwrap(); // we know the path is not empty, so safe unwrap on the last segment
                let segment_ident = segment.ident.to_string();

                match segment_ident.as_str() {
                    "u8" => Self::new_primitive(U8, opts),
                    "u16" => Self::new_primitive(U16, opts),
                    "u32" => Self::new_primitive(U32, opts),
                    "u64" => Self::new_primitive(U64, opts),
                    "i8" => Self::new_primitive(I8, opts),
                    "i16" => Self::new_primitive(I16, opts),
                    "i32" => Self::new_primitive(I32, opts),
                    "i64" => Self::new_primitive(I64, opts),

                    // The AST for Vecs is horrible, so we'll do it in another function.
                    "Vec" => return Self::from_vec_type(segment, opts),

                    // If the type's name does not match anything above, then we'll assume that it
                    // is a user defined type, which is either a struct or an enum (type aliases
                    // are not allowed since we can't use derive macros on them).
                    _ => match &opts.dispatch {
                        Some(dispatch) => Self::new_collection(
                            CollectionType::Enum {
                                ident: path.clone(),
                                dispatch: dispatch.clone(),
                            },
                            opts,
                        ),
                        None => Self::new_collection(
                            CollectionType::Struct {
                                ident: path.clone(),
                            },
                            opts,
                        ),
                    },
                }
            }
            _ => return make_err(typ, "unexpected type"),
        };

        Ok(ret)
    }

    fn from_array_type(
        array: &syn::TypeArray,
        opts: &FieldOptions,
    ) -> Result<DataType, syn::Error> {
        let elem_type = Self::from_syn_type(&array.elem, opts)?;
        let elem_count = match &array.len {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) => lit.base10_parse::<usize>()?,
            _ => return make_err(&array.len, "expected integer literal"),
        };
        let typ = match elem_type {
            // If the elements of the array are u8s, then we'll treat the array as a ByteArray
            // type, instead of a list of u8s.
            DataType::Primitive(data) if data.typ == PrimitiveType::U8 => Self::new_primitive(
                PrimitiveType::ByteArray {
                    size: SizeHint::Static(elem_count),
                    subdissector: opts.subdissector.clone(),
                },
                opts,
            ),
            _ => Self::new_collection(
                CollectionType::List {
                    elem: Box::new(elem_type),
                    len: SizeHint::Static(elem_count),
                },
                opts,
            ),
        };
        Ok(typ)
    }

    fn from_vec_type(segment: &syn::PathSegment, opts: &FieldOptions) -> syn::Result<Self> {
        debug_assert!(segment.ident == "Vec");

        let arg = match &segment.arguments {
            syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                args,
                ..
            }) if args.len() == 1 => args.last().unwrap(),
            _ => return make_err(&segment.arguments, "expected exactly one generic argument"),
        };
        let inner_type = match arg {
            syn::GenericArgument::Type(inner_type) => inner_type,
            _ => return make_err(arg, "expected type argument"),
        };

        let elem_type = Self::from_syn_type(inner_type, opts)?;
        match elem_type {
            DataType::Primitive(data) if data.typ == PrimitiveType::U8 => {
                let typ = match (&opts.size_hint, &opts.consume_with, &opts.subdissector) {
                    (None, None, None) => {
                        return make_err(segment, "unable to determine size of these bytes")
                    }
                    (None, None, Some(subd)) => Self::new_collection(
                        CollectionType::Bytes {
                            consume: ConsumeBytes::Subdissector(subd.clone()),
                        },
                        opts,
                    ),
                    (None, Some(consume_fn), None) => Self::new_collection(
                        CollectionType::Bytes {
                            consume: ConsumeBytes::ConsumeWith(consume_fn.clone()),
                        },
                        opts,
                    ),
                    (_, Some(_), Some(_)) => {
                        return make_err(
                            segment,
                            "only one of `consume_with` or `subdissector` can be specified",
                        )
                    }
                    (Some(len_field), None, subd) => Self::new_primitive(
                        PrimitiveType::ByteArray {
                            size: SizeHint::Field(len_field.clone()),
                            subdissector: subd.clone(),
                        },
                        opts,
                    ),
                    (Some(_), Some(_), None) => {
                        return make_err(
                            segment,
                            "cannot use `len_field` togther with `consume_with`",
                        )
                    }
                };
                Ok(typ)
            }
            _ if opts.size_hint.is_none() => {
                make_err(segment, "length of list cannot be determined")
            }
            _ => {
                let elem = Box::new(elem_type);
                let len = SizeHint::Field(opts.size_hint.clone().unwrap()); // safe to unwrap here, branch above ensures Some
                Ok(Self::new_collection(
                    CollectionType::List { elem, len },
                    opts,
                ))
            }
        }
    }

    /// If this is a repeated field using a previous field for its length, returns that field.
    pub(crate) fn get_len_field(&self) -> Option<&syn::Ident> {
        // The `len_field` annotation can appear in two places. For primitive types, it may
        // appear for ByteArray types. For collection types, it may appear for List types.
        match self {
            DataType::Primitive(data) => match &data.typ {
                PrimitiveType::ByteArray {
                    size: SizeHint::Field(ident),
                    ..
                } => Some(ident),
                _ => None,
            },
            DataType::Collection(data) => match &data.typ {
                CollectionType::List {
                    len: SizeHint::Field(ident),
                    ..
                } => Some(ident),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod test_datatype_construction {
    use super::*;

    #[test]
    fn primitive_types_with_default_options() -> syn::Result<()> {
        use PrimitiveType::*;

        let tests = [
            (parse_quote! { u8 }, U8),
            (parse_quote! { u16 }, U16),
            (parse_quote! { u32 }, U32),
            (parse_quote! { u64 }, U64),
        ];
        let opts = FieldOptions::default();

        for (tt, typ) in tests {
            let got = DataType::from_syn_type(&tt, &opts)?;
            let want = DataType::new_primitive(typ, &opts);

            assert_eq!(got, want);
        }

        Ok(())
    }

    #[test]
    fn byte_array_from_array() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { [u8; 7] };
        let opts = FieldOptions::default();

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_primitive(
            PrimitiveType::ByteArray {
                size: SizeHint::Static(7),
                subdissector: None,
            },
            &opts,
        );

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn byte_array_from_u8_vec() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { Vec<u8> };

        let len_ident = format_ident!("len");
        let opts = FieldOptions {
            size_hint: Some(len_ident.clone()),
            ..Default::default()
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_primitive(
            PrimitiveType::ByteArray {
                size: SizeHint::Field(len_ident),
                subdissector: None,
            },
            &opts,
        );

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn bytes_without_size_hint_fails() {
        let input_type: syn::Type = parse_quote! { Vec<u8> };
        let opts = FieldOptions::default(); // no size hint

        let got = DataType::from_syn_type(&input_type, &opts);
        assert!(got.is_err());
    }

    #[test]
    fn list_without_size_hint_fails() {
        let input_type: syn::Type = parse_quote! { Vec<Foo> };
        let opts = FieldOptions::default(); // no size hint

        let got = DataType::from_syn_type(&input_type, &opts);
        assert!(got.is_err());
    }

    #[test]
    fn struct_type() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { path::to::FooStruct };
        let type_path: syn::TypePath = parse_quote! { path::to::FooStruct };
        let opts = FieldOptions::default();

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(CollectionType::Struct { ident: type_path }, &opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn enum_type() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { path::to::FooEnum };
        let type_path: syn::TypePath = parse_quote! { path::to::FooEnum };

        // Enums are identified by having the `dispatch` field option set.
        let opts = FieldOptions {
            dispatch: Some(format_ident!("dispatch")),
            ..Default::default()
        };

        let collection = CollectionType::Enum {
            ident: type_path,
            dispatch: format_ident!("dispatch"),
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn list_of_primitives() -> syn::Result<()> {
        let tests: [(syn::Type, syn::Type, syn::Type); 3] = [
            // We're compressing two tests into one: getting a DataType from 1) an array, and 2) a
            // vector.
            (
                parse_quote! { [u16; 7] },
                parse_quote! { Vec<u16> },
                parse_quote! { u16 },
            ),
            (
                parse_quote! { [u32; 7] },
                parse_quote! {Vec<u32>},
                parse_quote! { u32 },
            ),
            (
                parse_quote! { [u64; 7] },
                parse_quote! {Vec<u64> },
                parse_quote! { u64 },
            ),
        ];

        let array_opts = FieldOptions::default();
        let vec_opts = FieldOptions {
            size_hint: Some(format_ident!("len")),
            ..Default::default()
        };

        for (array_type, vec_type, elem_type) in tests {
            let elem_type = DataType::from_syn_type(&elem_type, &array_opts)?;

            let collection = CollectionType::List {
                len: SizeHint::Static(7),
                elem: Box::new(elem_type.clone()),
            };

            // Test from array...
            let got = DataType::from_syn_type(&array_type, &array_opts)?;
            let want = DataType::new_collection(collection, &array_opts);

            assert_eq!(got, want);

            // ...and from Vec
            let collection = CollectionType::List {
                len: SizeHint::Field(format_ident!("len")),
                elem: Box::new(elem_type),
            };

            let got = DataType::from_syn_type(&vec_type, &vec_opts)?;
            let want = DataType::new_collection(collection, &vec_opts);

            assert_eq!(got, want);
        }

        Ok(())
    }

    #[test]
    fn list_of_user_types() -> syn::Result<()> {
        // First test for arrays...
        let input_type: syn::Type = parse_quote! { [FooStruct; 7] };

        let opts = FieldOptions::default();

        let elem_type = DataType::from_syn_type(&parse_quote! { FooStruct }, &opts)?;
        let collection = CollectionType::List {
            len: SizeHint::Static(7),
            elem: Box::new(elem_type.clone()),
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);

        // ...and now from vectors.
        let input_type: syn::Type = parse_quote! { Vec<FooStruct> };

        let opts = FieldOptions {
            size_hint: Some(format_ident!("len")),
            ..Default::default()
        };

        let collection = CollectionType::List {
            len: SizeHint::Field(format_ident!("len")),
            elem: Box::new(elem_type),
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn vec_of_arrays_is_ok() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { Vec<[u16; 7]> };

        let opts = FieldOptions {
            size_hint: Some(format_ident!("len")),
            ..Default::default()
        };

        let elem_type = DataType::new_collection(
            CollectionType::List {
                len: SizeHint::Static(7),
                elem: Box::new(DataType::new_primitive(
                    PrimitiveType::U16,
                    &FieldOptions::default(),
                )),
            },
            &FieldOptions::default(),
        );
        let collection = CollectionType::List {
            elem: Box::new(elem_type),
            len: SizeHint::Field(format_ident!("len")),
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn array_of_vecs_is_ok() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { [Vec<u16>; 7] };

        let vec_opts = FieldOptions {
            size_hint: Some(format_ident!("len")),
            ..Default::default()
        };

        let elem_type = DataType::new_collection(
            CollectionType::List {
                len: SizeHint::Field(format_ident!("len")),
                elem: Box::new(DataType::new_primitive(
                    PrimitiveType::U16,
                    &FieldOptions::default(),
                )),
            },
            &vec_opts,
        );
        let collection = CollectionType::List {
            len: SizeHint::Static(7),
            elem: Box::new(elem_type),
        };

        let got = DataType::from_syn_type(&input_type, &vec_opts)?; // the options should "drill" down to the vector
        let want = DataType::new_collection(collection, &vec_opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn array_of_bytes_is_ok() {
        // Since bytes can be represented as a [u8; _], we should make sure there's no confusion
        // somehow
        let input_type: syn::Type = parse_quote! { [[u8; 7]; 7] };

        let opts = FieldOptions::default();

        let elem_type = DataType::new_primitive(
            PrimitiveType::ByteArray {
                size: SizeHint::Static(7),
                subdissector: None,
            },
            &opts,
        );

        let collection = CollectionType::List {
            len: SizeHint::Static(7),
            elem: Box::new(elem_type),
        };

        let got = DataType::from_syn_type(&input_type, &opts).unwrap();
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);
    }

    #[test]
    fn nested_array_is_ok() -> syn::Result<()> {
        let input_type: syn::Type = parse_quote! { [[u16; 7]; 7] };

        let opts = FieldOptions::default();

        let elem_type = DataType::new_collection(
            CollectionType::List {
                len: SizeHint::Static(7),
                elem: Box::new(DataType::new_primitive(PrimitiveType::U16, &opts)),
            },
            &opts,
        );
        let collection = CollectionType::List {
            len: SizeHint::Static(7),
            elem: Box::new(elem_type),
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_collection(collection, &opts);

        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn bytes_using_len_and_decode_with_is_ok() -> syn::Result<()> {
        // Something like
        //   #[wsdf(len_field = "len", decode_with = "decode_with"")]
        //   bytes: Vec<u8>
        let input_type: syn::Type = parse_quote! { Vec<u8> };

        let opts = FieldOptions {
            size_hint: Some(format_ident!("len")),
            decode_with: Some(parse_quote! { decode_with }),
            ..Default::default()
        };

        let primitive = PrimitiveType::ByteArray {
            size: SizeHint::Field(format_ident!("len")),
            subdissector: None,
        };

        let got = DataType::from_syn_type(&input_type, &opts)?;
        let want = DataType::new_primitive(primitive, &opts);

        assert_eq!(got, want);

        Ok(())
    }
}

// This block holds methods related to dissecting the field.
impl DataType {
    /// For dissection. Builds the code needed to retrieve the hf for this field. Note that some
    /// fields may not have a hf registered, e.g. struct/enum fields or bytes meant for
    /// subdissectors.
    pub(crate) fn retrieve_hf(&self, root_ident: &syn::Ident) -> Option<proc_macro2::TokenStream> {
        let expr = quote! {
            let #WSDF_HF = <#root_ident as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Get(#WSDF_PREFIX_NEXT.as_str()),
            ).unwrap_or_else(|| panic!("expected hf for {} to exist", #WSDF_PREFIX_NEXT));
        };

        match self {
            DataType::Primitive(primitive) => match &primitive.typ {
                PrimitiveType::ByteArray {
                    subdissector: Some(_),
                    ..
                } => None,
                _ => Some(expr),
            },
            DataType::Collection(data) => match &data.typ {
                CollectionType::Bytes {
                    consume: ConsumeBytes::ConsumeWith(_),
                } => Some(expr),
                CollectionType::List { elem, .. } => elem.retrieve_hf(root_ident),
                _ => None,
            },
        }
    }

    /// For dissection. Builds the code needed to emit the field, which just means extracting
    /// the field's value from the TVB and keeping it in a variable.
    pub(crate) fn emit_field(&self, field_ident: &syn::Ident) -> Option<proc_macro2::TokenStream> {
        match self {
            DataType::Primitive(data) => data.emit_field(field_ident),
            DataType::Collection(_) => None,
        }
    }

    /// For dissection. Builds the code which adds this field to our virtual tree.
    pub(crate) fn add_to_tree(
        &self,
        field_ident: &syn::Ident,
        field_name: &str,
        root_ident: &syn::Ident,
    ) -> proc_macro2::TokenStream {
        match self {
            DataType::Primitive(data) => data.add_to_tree(field_ident, root_ident),
            DataType::Collection(data) => data.add_to_tree(field_ident, field_name, root_ident),
        }
    }

    /// Adds this field's value to our running context.
    pub(crate) fn add_to_fields_store(&self, field_ident: &syn::Ident) -> Option<syn::Stmt> {
        match self {
            DataType::Primitive(data) => data.add_to_fields_store(field_ident),
            // Collection types cannot be emitted (and thus cannot be added to the store), so
            // we do not produce any code for that.
            DataType::Collection(_) => None,
        }
    }

    /// Produces code which initializes the WSDF_TAP_CTX variable, if needed.
    pub(crate) fn create_ctx(&self, field_ident: &syn::Ident) -> Option<syn::Stmt> {
        if !self.requires_ctx() {
            return None;
        }
        // The `field` attribute in our context is slightly tricky. Only primitive types can be
        // emitted and added to the context. For collection type, we will just add ().
        let field: syn::Expr = match self {
            DataType::Primitive(_) => parse_quote! { #field_ident },
            DataType::Collection(_) => parse_quote! { () },
        };
        Some(Self::create_ctx_with_field(&field))
    }

    pub(crate) fn create_ctx_with_field(field_val: &syn::Expr) -> syn::Stmt {
        parse_quote! {
            let #WSDF_TAP_CTX = wsdf::tap::Context {
                field: #field_val,
                fields: #WSDF_FIELDS_STORE,
                pinfo: #WSDF_PINFO,
                packet: #WSDF_TVB_BUF,
                offset: (#WSDF_START + #WSDF_OFFSET) as usize,
            };
        }
    }

    /// Checks if this type requires a tap context to be initialized.
    fn requires_ctx(&self) -> bool {
        match self {
            DataType::Primitive(data) => !data.taps.is_empty() || data.decode_with.is_some(),
            DataType::Collection(data) => !data.taps.is_empty() || data.has_consume_with(),
        }
    }

    pub(crate) fn call_taps(&self) -> impl Iterator<Item = syn::Stmt> + '_ {
        let taps = match self {
            DataType::Primitive(data) => &data.taps,
            DataType::Collection(data) => &data.taps,
        };
        taps.iter().map(|tap_fn| {
            parse_quote! {
                wsdf::tap::handle_tap(&#WSDF_TAP_CTX, #tap_fn);
            }
        })
    }
}

// This block holds methods related to registering a field.
impl DataType {
    /// For registration. Builds the code needed to register a user-defined type (one which derives
    /// `ProtocolField`). If the field is not a user-defined type, then we return None.
    pub(crate) fn register_user_type(
        &self,
        field_name: &str,
        field_blurb: &Option<String>,
    ) -> Option<proc_macro2::TokenStream> {
        match self {
            DataType::Primitive(_) => None,
            DataType::Collection(data) => data.register_user_type(field_name, field_blurb),
        }
    }

    /// For registration. Builds the code needed to create a header field (Wireshark's
    /// `hf_register_info` struct type).
    pub(crate) fn create_hf(
        &self,
        is_unit_tuple: bool,
        root_ident: &syn::Ident,
        field_name: &str,
        field_blurb: &Option<String>,
    ) -> Option<proc_macro2::TokenStream> {
        use CollectionType::*;

        let create_expr = || {
            Some(Self::create_hf_impl(
                is_unit_tuple,
                root_ident,
                field_name,
                field_blurb,
                &self.ws_type(),
                &self.ws_display(),
            ))
        };

        match self {
            DataType::Primitive(primitive) => match &primitive.typ {
                PrimitiveType::ByteArray {
                    subdissector: Some(_),
                    ..
                } => None,
                _ => create_expr(),
            },
            DataType::Collection(collection) => match &collection.typ {
                List { elem, .. } => {
                    elem.create_hf(is_unit_tuple, root_ident, field_name, field_blurb)
                }
                Bytes { consume } => match consume {
                    ConsumeBytes::ConsumeWith(_) => create_expr(),
                    ConsumeBytes::Subdissector(_) => None,
                },
                Struct { .. } | Enum { .. } => None,
            },
        }
    }

    fn create_hf_impl(
        is_unit_tuple: bool,
        root_ident: &syn::Ident,
        field_name: &str,
        field_blurb: &Option<String>,
        ws_type: &syn::Path,
        ws_display: &syn::Expr,
    ) -> proc_macro2::TokenStream {
        let field_name = field_name_expr(field_name, is_unit_tuple);
        let field_blurb = field_blurb_expr(field_blurb, is_unit_tuple);

        // Here, we need a static location for an integer. A pointer to this location is given to
        // Wireshark. We use Box::leak as a convenient way to get a "static" location. This can
        // be optimized!
        //
        // One solution is to preallocate an array guaranteed to have enough slots for all header
        // fields. Then we'll use up slots in the array as we register each field.
        //
        // @todo: optimize this leak stuff
        let declare_hf: syn::Stmt = parse_quote! {
            let #WSDF_HF = std::boxed::Box::leak(
                std::boxed::Box::new(-1i32),
            ) as *mut std::ffi::c_int;
        };
        let keep_hf: syn::Stmt = parse_quote! {
            unsafe {
                // Store the hf's pointer, and check that we did not override anything (this hf
                // should be unique!)
                let _p = <#root_ident as wsdf::ProtocolField>::hf_map(
                    wsdf::HfMapOp::Set(&#WSDF_PREFIX_NEXT, #WSDF_HF),
                );
                debug_assert!(_p.is_none());
            }
        };
        let append_hf: syn::Stmt = parse_quote! {
            #WSDF_HFS.push(wsdf::epan_sys::hf_register_info {
                p_id: #WSDF_HF,
                hfinfo: wsdf::epan_sys::header_field_info {
                    name: #field_name,
                    abbrev: std::boxed::Box::leak(
                            std::ffi::CString::new(#WSDF_PREFIX_NEXT).unwrap().into_boxed_c_str(), // @todo: handle unwrap here
                        ).as_ptr() as *const std::ffi::c_char,
                    type_: #ws_type,
                    display: #ws_display,
                    strings: std::ptr::null(),
                    bitmask: 0,
                    blurb: #field_blurb,
                    id: -1,
                    parent: 0,
                    ref_type: wsdf::epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: std::ptr::null_mut(),
                 },
            });
        };

        quote! {
            #declare_hf
            #keep_hf
            #append_hf
        }
    }

    /// For registration. Builds the code needed to register a subdissector, iff the field needs to
    /// be subdissected.
    pub(crate) fn register_subdissector(
        &self,
        root_ident: &syn::Ident,
    ) -> Option<proc_macro2::TokenStream> {
        self.get_subdissector()
            .map(|subdissector| subdissector.register(root_ident))
    }

    /// Retrieves the subdissector registered for this type, if any.
    #[rustfmt::skip]
    fn get_subdissector(&self) -> Option<&Subdissector> {
        // Of course, subdissectors should only appear on bytes-ish types.
        match self {
            DataType::Primitive(Primitive {
                typ: PrimitiveType::ByteArray {
                    subdissector: Some(subdissector),
                    ..
                },
                ..
            }) |
            DataType::Collection(Collection {
                typ: CollectionType::Bytes {
                    consume: ConsumeBytes::Subdissector(subdissector),
                },
                ..
            }) => Some(subdissector),
            _ => None,
        }
    }

    #[rustfmt::skip]
    pub(crate) fn get_subdissector_mut(&mut self) -> Option<&mut Subdissector> {
        match self {
            DataType::Primitive(Primitive {
                typ: PrimitiveType::ByteArray {
                    subdissector: Some(subdissector),
                    ..
                },
                ..
            }) |
            DataType::Collection(Collection {
                typ: CollectionType::Bytes {
                    consume: ConsumeBytes::Subdissector(subdissector),
                },
                ..
            }) => Some(subdissector),
            _ => None,
        }
    }
}

/// Returns an expression (char ptr) for the "blurb" of a field. The blurb is just the description
/// which appears at the bottom.
fn field_blurb_expr(field_blurb: &Option<String>, is_unit_tuple: bool) -> syn::Expr {
    let field_blurb: syn::Expr = match field_blurb {
        Some(s) => cstr!(s),
        None => parse_quote! { std::ptr::null() },
    };
    if is_unit_tuple {
        // Unit tuples are meant to take on the description at wherever it is used. For instance,
        //
        // struct Packet {
        //   /// Source IP address.
        //   src: IpAddr,
        // }
        // struct IpAddr([u8; 4]);
        //
        // Here we would want the blurb of the `src` field to show "Source IP address". We can
        // access this from the WSDF_FIELD_BLURB variable.
        parse_quote! { #WSDF_FIELD_BLURB.unwrap_or(#field_blurb) }
    } else {
        field_blurb
    }
}

fn field_name_expr(field_name: &str, is_unit_tuple: bool) -> syn::Expr {
    let field_name: syn::Expr = cstr!(field_name);
    if is_unit_tuple {
        // Similar to how we handled field blurbs. The name of the field in a unit tuple should
        // be the field's name at wherever it is used.
        //
        // struct Packet {
        //   /// Source IP address.
        //   src: IpAddr,
        // }
        // struct IpAddr([u8; 4]);
        //
        // Unit tuples have no "field names". We need to retrieve it from the WSDF_FIELD_IDENT
        // variable. In this case, we would get "src".
        parse_quote! { #WSDF_FIELD_IDENT.unwrap_or(#field_name) }
    } else {
        field_name
    }
}

impl Primitive {
    fn new(typ: PrimitiveType, opts: &FieldOptions) -> Self {
        Self {
            typ,
            hidden: opts.hidden.unwrap_or(false),
            taps: opts.taps.clone(),
            is_used_later: false, // to be set later
            should_save: opts.save.unwrap_or(false),
            decode_with: opts.decode_with.clone(),
            ws_type: opts.ws_type.clone(),
            ws_enc: opts.ws_enc.clone(),
            ws_display: opts.ws_display.clone(),
        }
    }

    fn default_ws_type(&self) -> &'static str {
        self.typ.default_ws_type()
    }

    fn default_ws_enc(&self) -> &'static str {
        self.typ.default_ws_enc()
    }

    fn default_ws_display(&self) -> (&'static str, Option<&'static str>) {
        self.typ.default_ws_display()
    }

    pub(crate) fn ws_type(&self) -> syn::Path {
        let ws_type = match &self.ws_type {
            Some(typ) => typ.as_str(),
            None => self.default_ws_type(),
        };
        format_ws_type(ws_type)
    }

    pub(crate) fn ws_enc(&self) -> syn::Path {
        let ws_enc = match &self.ws_enc {
            Some(ws_enc) => ws_enc.as_str(),
            None => self.default_ws_enc(),
        };
        format_ws_enc(ws_enc)
    }

    pub(crate) fn ws_display(&self) -> syn::Expr {
        let default_display = FieldDisplayPair::new(self.default_ws_display());
        let ws_display = self.ws_display.as_ref().unwrap_or(&default_display);
        ws_display.to_expr()
    }

    fn add_to_tree(
        &self,
        field_ident: &syn::Ident,
        root_ident: &syn::Ident,
    ) -> proc_macro2::TokenStream {
        // For primitive types, we know its size before starting to decode the field. Thus we can
        // cheat and skip all the work, and just increment the offset.
        if self.hidden {
            let size = self.typ.size_expr();
            return quote! { #WSDF_OFFSET += #size; };
        }

        match &self.decode_with {
            None => self.typ.add_to_tree(&self.ws_enc(), root_ident),
            Some(decode_fn_ident) => self.add_to_tree_decode_with(field_ident, decode_fn_ident),
        }
    }

    fn add_to_tree_decode_with(
        &self,
        field_ident: &proc_macro2::Ident,
        decode_fn_ident: &syn::Path,
    ) -> proc_macro2::TokenStream {
        use PrimitiveType::*;

        let size = self.typ.size_expr();

        // Each type has a different function in Wireshark for adding it to the tree with a custom
        // format. So we'll have to map each type to a string here and then build out the real
        // function identifier.
        //
        // We'll also need an expression for the value of the field (required by the
        // proto_tree_add... function).
        let (type_name, value) = match self.typ {
            U8 | U16 | U32 => ("uint", quote! { #field_ident as u32 }),
            I8 | I16 | I32 => ("int", quote! { #field_ident as i32 }),
            U64 => ("uint64", quote! { #field_ident }),
            I64 => ("int64", quote! { #field_ident }),
            ByteArray { .. } => ("bytes", quote! { #field_ident.as_ptr() }),
        };
        let proto_tree_add_func_ident = format_ident!("proto_tree_add_{}_format_value", type_name);

        let call_decode_fn = quote! {
            let #WSDF_UI_STR = wsdf::tap::handle_decode_with(&#WSDF_TAP_CTX, #decode_fn_ident);
            let #WSDF_UI_STR = std::ffi::CString::new(
                std::string::ToString::to_string(&#WSDF_UI_STR),
            ).unwrap(); // @todo: handle unwrap here
        };
        let add_node = quote! {
            unsafe {
                wsdf::epan_sys::#proto_tree_add_func_ident(
                    #WSDF_PARENT_NODE,
                    #WSDF_HF,
                    #WSDF_TVB,
                    #WSDF_START + #WSDF_OFFSET,
                    #size,
                    #value,
                    #WSDF_UI_STR.as_ptr(),
                );
            }
        };
        let incr_offset = quote! {
            #WSDF_OFFSET += #size as std::ffi::c_int;
        };
        quote! {
            #call_decode_fn
            #add_node
            #incr_offset
        }
    }

    /// Returns whether the field should be emitted.
    fn should_emit(&self) -> bool {
        self.is_used_later
            || !self.taps.is_empty()
            || self.decode_with.is_some()
            || self.should_save
    }

    /// Produces code to get the value of the field and store in in a variable.
    fn emit_field(&self, field_ident: &syn::Ident) -> Option<proc_macro2::TokenStream> {
        use PrimitiveType::*;

        if !self.should_emit() {
            return None;
        }

        // A closure, for convenience, to grab an integer value from the TVB
        let get_int = |typ: &str| {
            let ws_enc = match typ {
                "guint8" | "gint8" => None,
                _ => Some(self.ws_enc()),
            };
            let func_name = format_ident!("tvb_get_{}", typ);
            quote! {
                let #field_ident = unsafe {
                    wsdf::epan_sys::#func_name(
                        #WSDF_TVB,
                        #WSDF_START + #WSDF_OFFSET,
                        #ws_enc // do not add a comma here!
                    )
                };
            }
        };

        let ret = match &self.typ {
            U8 => get_int("guint8"),
            U16 => get_int("guint16"),
            U32 => get_int("guint32"),
            U64 => get_int("guint64"),
            I8 => get_int("gint8"),
            I16 => get_int("gint16"),
            I32 => get_int("gint32"),
            I64 => get_int("gint64"),
            ByteArray { size, .. } => {
                let size_expr = size.as_syn_expr();
                let start_idx: syn::Expr = parse_quote! {
                    (#WSDF_START + #WSDF_OFFSET) as usize
                };

                quote! {
                    debug_assert!(#start_idx+#size_expr <= #WSDF_TVB_BUF.len());
                    let #field_ident = &#WSDF_TVB_BUF[#start_idx..#start_idx+#size_expr];
                }
            }
        };

        Some(ret)
    }

    /// Produces code which adds this field to our store.
    fn add_to_fields_store(&self, field_ident: &syn::Ident) -> Option<syn::Stmt> {
        use PrimitiveType::*;

        // A field which is not emitted cannot possibly be added to the store. So we skip it.
        if !self.should_save {
            return None;
        }

        let add_fn = match self.typ {
            U8 => quote! { insert_u8 },
            U16 => quote! { insert_u16 },
            U32 => quote! { insert_u32 },
            U64 => quote! { insert_u64 },
            I8 => quote! { insert_i8 },
            I16 => quote! { insert_i16 },
            I32 => quote! { insert_i32 },
            I64 => quote! { insert_i64 },
            ByteArray { .. } => quote! { insert_bytes },
        };

        Some(parse_quote! {
            #WSDF_FIELDS_STORE.#add_fn(&#WSDF_PREFIX_NEXT, #field_ident);
        })
    }
}

impl Collection {
    fn new(typ: CollectionType, opts: &FieldOptions) -> Self {
        Self {
            typ,
            hidden: opts.hidden.unwrap_or(false),
            taps: opts.taps.clone(),
        }
    }

    fn default_ws_type(&self) -> &'static str {
        self.typ.default_ws_type()
    }

    fn default_ws_display(&self) -> (&'static str, Option<&'static str>) {
        self.typ.default_ws_display()
    }

    fn ws_type(&self) -> syn::Path {
        match &self.typ {
            CollectionType::List { elem, .. } => elem.ws_type(),
            _ => format_ws_type(self.default_ws_type()),
        }
    }

    fn ws_display(&self) -> syn::Expr {
        match &self.typ {
            CollectionType::List { elem, .. } => elem.ws_display(),
            _ => FieldDisplayPair::new(self.default_ws_display()).to_expr(),
        }
    }

    fn add_to_tree(
        &self,
        field_ident: &syn::Ident,
        field_name: &str,
        root_ident: &syn::Ident,
    ) -> proc_macro2::TokenStream {
        // @todo: handle hidden fields
        self.typ.add_to_tree(field_ident, field_name, root_ident)
    }

    fn register_user_type(
        &self,
        field_name: &str,
        field_blurb: &Option<String>,
    ) -> Option<proc_macro2::TokenStream> {
        use CollectionType::*;
        match &self.typ {
            List { elem, .. } => elem.register_user_type(field_name, field_blurb),
            Struct { ident } => {
                let field_name: syn::Expr = cstr!(field_name);
                let field_blurb = match field_blurb {
                    None => quote! { std::ptr::null() },
                    Some(s) => cstr!(s),
                };
                Some(quote! {
                    <#ident as wsdf::ProtocolField>::register(
                        &#WSDF_PREFIX_NEXT,
                        #WSDF_PROTO_ID,
                        wsdf::FieldIdent::new(#field_name),
                        wsdf::FieldBlurb::new(#field_blurb),
                    );
                })
            }
            Enum { ident, .. } => Some(quote! {
                <#ident as wsdf::ProtocolField>::register(
                    &#WSDF_PREFIX_NEXT,
                    #WSDF_PROTO_ID,
                    wsdf::FieldIdent::null(),
                    wsdf::FieldBlurb::null(),
                );
            }),
            Bytes { .. } => None,
        }
    }

    /// Checks if this type is a Bytes variant with a custom consume_with.
    fn has_consume_with(&self) -> bool {
        matches!(
            self.typ,
            CollectionType::Bytes {
                consume: ConsumeBytes::ConsumeWith(_),
            }
        )
    }
}

impl PrimitiveType {
    fn size_expr(&self) -> syn::Expr {
        use PrimitiveType::*;
        let n = match self {
            U8 | I8 => 1,
            U16 | I16 => 2,
            U32 | I32 => 4,
            U64 | I64 => 8,
            ByteArray { size, .. } => match size {
                SizeHint::Static(n) => *n,
                SizeHint::Field(ident) => return parse_quote! { #ident },
            },
        };
        parse_quote! { #n as std::ffi::c_int }
    }

    fn default_ws_type(&self) -> &'static str {
        use PrimitiveType::*;
        match self {
            U8 => "FT_UINT8",
            U16 => "FT_UINT16",
            U32 => "FT_UINT32",
            U64 => "FT_UINT64",
            I8 => "FT_INT8",
            I16 => "FT_INT16",
            I32 => "FT_INT32",
            I64 => "FT_INT64",
            ByteArray { .. } => "FT_BYTES",
        }
    }

    fn default_ws_enc(&self) -> &'static str {
        use PrimitiveType::*;
        match self {
            U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 => "ENC_BIG_ENDIAN", // bigendian by default?
            ByteArray { .. } => "ENC_NA",
        }
    }

    fn default_ws_display(&self) -> (&'static str, Option<&'static str>) {
        use PrimitiveType::*;
        match self {
            U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 => ("BASE_DEC", None),
            ByteArray { .. } => ("SEP_COLON", Some("BASE_SHOW_ASCII_PRINTABLE")),
        }
    }

    fn add_to_tree(&self, ws_enc: &syn::Path, root_ident: &syn::Ident) -> proc_macro2::TokenStream {
        use PrimitiveType::*;

        let add_item = |size: &syn::Expr| -> syn::Stmt {
            parse_quote! {
                unsafe {
                    wsdf::epan_sys::proto_tree_add_item(
                        #WSDF_PARENT_NODE,
                        #WSDF_HF,
                        #WSDF_TVB,
                        #WSDF_START + #WSDF_OFFSET,
                        #size as std::ffi::c_int,
                        #ws_enc,
                    );
                }
            }
        };

        let size = match self {
            U8 | I8 => parse_quote! { 1 },
            U16 | I16 => parse_quote! { 2 },
            U32 | I32 => parse_quote! { 4 },
            U64 | I64 => parse_quote! { 8 },
            ByteArray { size, subdissector } => match subdissector {
                None => size.as_syn_expr(),
                Some(subdissector) => {
                    return subdissector.try_subdissector(root_ident, Some(size.as_syn_expr()))
                }
            },
        };

        let add_item = add_item(&size);
        let incr_offset = quote! {
            #WSDF_OFFSET += #size as std::ffi::c_int;
        };

        quote! {
            #add_item
            #incr_offset
        }
    }
}

impl CollectionType {
    fn default_ws_type(&self) -> &'static str {
        use CollectionType::*;
        match self {
            List { elem, .. } => elem.default_ws_type(),
            Bytes { .. } => "FT_BYTES",
            Struct { .. } | Enum { .. } => "FT_NONE",
        }
    }

    fn default_ws_display(&self) -> (&'static str, Option<&'static str>) {
        use CollectionType::*;
        match self {
            List { elem, .. } => elem.default_ws_display(),
            Struct { .. } | Enum { .. } | Bytes { .. } => ("BASE_NONE", None),
        }
    }

    fn add_to_tree(
        &self,
        field_ident: &syn::Ident,
        field_name: &str,
        root_ident: &syn::Ident,
    ) -> proc_macro2::TokenStream {
        use CollectionType::*;

        match self {
            List { elem, len } => {
                let elem_instructions = elem.add_to_tree(field_ident, field_name, root_ident);
                let len = len.as_syn_expr();
                quote! { for i in 0..#len { #elem_instructions } }
            }
            // Structs must call the corresponding ProtocolField::dissect routines. It must not
            // directly add nodes to the virtual tree in this scope, or we'll be double
            // counting. Thus we have the explicit return here.
            //
            // Similar for enums below.
            Struct { ident } => {
                let subtree_label: syn::Expr = cstr!(field_name);
                quote! {
                    #WSDF_OFFSET += <#ident as wsdf::ProtocolField>::dissect(
                        #WSDF_START + #WSDF_OFFSET,
                        #WSDF_TVB,
                        #WSDF_PARENT_NODE,
                        &#WSDF_PREFIX_NEXT,
                        wsdf::VariantDispatch::None,
                        wsdf::SubtreeLabel::new(#subtree_label),
                        #WSDF_TVB_BUF,
                        #WSDF_PINFO,
                        #WSDF_PROTO_TREE_ROOT,
                        #WSDF_FIELDS_STORE,
                    );
                }
            }
            Enum { ident, dispatch } => {
                let dispatch_fn_ident = format_ident!("dispatch_{}", dispatch);
                quote! {
                    #WSDF_OFFSET += <#ident as wsdf::ProtocolField>::dissect(
                        #WSDF_START + #WSDF_OFFSET,
                        #WSDF_TVB,
                        #WSDF_PARENT_NODE,
                        &#WSDF_PREFIX_NEXT,
                        wsdf::VariantDispatch::Index(#ident::#dispatch_fn_ident(&#dispatch) as usize),
                        wsdf::SubtreeLabel::null(),
                        #WSDF_TVB_BUF,
                        #WSDF_PINFO,
                        #WSDF_PROTO_TREE_ROOT,
                        #WSDF_FIELDS_STORE,
                    );
                }
            }
            Bytes { consume } => match consume {
                ConsumeBytes::ConsumeWith(consume_fn) => {
                    let call_consume_fn = quote! {
                        debug_assert!(#WSDF_TAP_CTX.offset <= #WSDF_TVB_BUF.len());

                        let (#WSDF_NR_BYTES_CONSUMED, #WSDF_UI_STR) =
                            wsdf::tap::handle_consume_with(&#WSDF_TAP_CTX, #consume_fn);
                        let #WSDF_UI_STR =
                            std::ffi::CString::new(std::string::ToString::to_string(&#WSDF_UI_STR))
                            .unwrap(); // @todo: handle the unwrap

                        // We need a pointer into some offset of the TVB. This is used as an
                        // argument to the proto_tree_add_XXX function.
                        let #WSDF_VALUE_P = if #WSDF_TAP_CTX.offset == #WSDF_TVB_BUF.len() {
                            std::ptr::null()
                        } else {
                            &#WSDF_TVB_BUF[#WSDF_TAP_CTX.offset as usize] as *const u8
                        };
                    };
                    let add_node = quote! {
                        unsafe {
                            wsdf::epan_sys::proto_tree_add_bytes_format_value(
                                #WSDF_PARENT_NODE,
                                #WSDF_HF,
                                #WSDF_TVB,
                                #WSDF_START + #WSDF_OFFSET,
                                #WSDF_NR_BYTES_CONSUMED as std::ffi::c_int,
                                #WSDF_VALUE_P,
                                #WSDF_UI_STR.as_ptr(),
                            );
                        }
                    };
                    let incr_offset = quote! {
                        #WSDF_OFFSET += #WSDF_NR_BYTES_CONSUMED as std::ffi::c_int;
                    };
                    quote! {
                        #call_consume_fn
                        #add_node
                        #incr_offset
                    }
                }
                ConsumeBytes::Subdissector(subdissector) => {
                    subdissector.try_subdissector(root_ident, None)
                }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SizeHint {
    Static(usize),
    Field(syn::Ident),
}

impl SizeHint {
    fn as_syn_expr(&self) -> syn::Expr {
        match self {
            SizeHint::Static(n) => parse_quote! { #n },
            SizeHint::Field(field) => parse_quote! { #field as usize },
        }
    }
}

const WSDF_HF: IdentHelper = IdentHelper("__wsdf_hf");
const WSDF_UI_STR: IdentHelper = IdentHelper("__wsdf_ui_str");
const WSDF_NR_BYTES_CONSUMED: IdentHelper = IdentHelper("__wsdf_nr_consumed");
const WSDF_VALUE_P: IdentHelper = IdentHelper("__wsdf_value_p");
