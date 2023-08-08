use std::collections::{HashMap, HashSet};

use quote::{format_ident, quote};
use syn::{parse_quote, punctuated::Punctuated, spanned::Spanned};

use crate::{attributes::*, types::*, util::*};

/// A logical group of data within some protocol, in terms of how we want them to be expressed in
/// code. Each `DataRoot` instance is responsible for generating unique identifiers for any global
/// declarations (functions or static collections).
#[derive(Debug)]
pub(crate) enum DataRoot<'a> {
    Struct {
        is_top_level: bool,
        data: DataTerminal<'a>,
        cfg: DataRootConfig,
    },
    Enum {
        ident: &'a syn::Ident,
        variants: Vec<EnumVariant<'a>>,
        cfg: DataRootConfig,
    },
}

/// A set of configuration common to all `DataRoot`s.
#[derive(Debug)]
pub(crate) struct DataRootConfig {
    pre_dissect: Vec<syn::Path>,
    post_dissect: Vec<syn::Path>,
}

#[derive(Debug)]
pub(crate) struct EnumVariant<'a> {
    data: DataTerminal<'a>,
}

/// Every `DataTerminal` will have its own dissection function.
#[derive(Debug)]
pub(crate) enum DataTerminal<'a> {
    UnitTuple {
        ident: &'a syn::Ident,
        rename: Option<String>,
        /// Type wrapped inside the unit tuple.
        inner: ProtoField<'a>,
    },
    /// The "opposite" of a unit tuple, i.e. when the fields are named.
    DataClass {
        ident: &'a syn::Ident,
        rename: Option<String>,
        fields: Vec<ProtoField<'a>>,
    },
}

impl DataRoot<'_> {
    pub(crate) fn dissection_fn(&self) -> syn::ItemFn {
        match self {
            DataRoot::Struct { data, cfg, .. } => data.dissection_fn(
                self,
                &format_ident!("dissect"),
                &cfg.pre_dissect,
                &cfg.post_dissect,
            ),
            DataRoot::Enum { variants, cfg, .. } => {
                // Each variant gets its own local dissection function, and we'll store their
                // pointers into an array. For instance...
                //
                // ```
                // enum Foo {
                //   Bar,
                //   Qux,
                // }
                // ```
                //
                // ...would generate something like
                //
                // ```
                // static __WSDF_DISSECT_FNS: [...] = [dissect_bar, dissect_qux];
                // fn dissect_bar(...) -> c_int {...}
                // fn dissect_qux(...) -> c_int {...}
                // ```
                //
                // This way we can index the array (0, 1, etc.) to get the dissection function for
                // any variant.

                let variants_snake_cased = variants
                    .iter()
                    .map(|variant| variant.data.ident().to_wsdf_snake_case());
                let func_idents = variants_snake_cased
                    .clone()
                    .map(|s| format_ident!("dissect_{}", s));

                let funcs =
                    variants
                        .iter()
                        .zip(func_idents.clone())
                        .map(|(variant, func_ident)| {
                            variant.data.dissection_fn(
                                self,
                                &func_ident,
                                &cfg.pre_dissect,
                                &cfg.post_dissect,
                            )
                        });

                let variant_subtree_labels: Vec<_> = variants
                    .iter()
                    .map(|variant| variant.data.subtree_label())
                    .collect();

                let nr_variants = variants.len();

                // This is the code we'll need to run once we know the "index" of the correct
                // variant to pick. We pretty much just pass all the parameters through,
                // transparently. We do need to update the prefix and subtree labels.
                let handle_dispatch_idx = quote! {
                    debug_assert!(
                        (0..#nr_variants).contains(&#WSDF_VARIANT_IDX),
                        "dispatch index out of bounds",
                    );

                    let #WSDF_PREFIX = #WSDF_PREFIX.to_owned() + "." + #WSDF_VARIANT_NAMES[#WSDF_VARIANT_IDX];

                    #WSDF_VARIANT_DISSECT_FNS[#WSDF_VARIANT_IDX](
                        #WSDF_START,
                        #WSDF_TVB,
                        #WSDF_PARENT_NODE,
                        &#WSDF_PREFIX,
                        wsdf::VariantDispatch::None,
                        #WSDF_VARIANT_SUBTREE_LABELS[#WSDF_VARIANT_IDX],
                        #WSDF_TVB_BUF,
                        #WSDF_PINFO,
                        #WSDF_PROTO_TREE_ROOT,
                        #WSDF_FIELDS_STORE,
                    )
                };

                parse_quote! {
                    #[allow(clippy::too_many_arguments, clippy::ptr_arg, clippy::int_plus_one)]
                    fn dissect<'a>(#DISSECTION_PARAMS) -> std::ffi::c_int {
                        static #WSDF_VARIANT_DISSECT_FNS: [for<'a> fn ( #DISSECTION_PARAMS )
                            -> std::ffi::c_int; #nr_variants] = [#(#func_idents),*];

                        static #WSDF_VARIANT_NAMES: [&'static str; #nr_variants]
                            = [#(#variants_snake_cased,)*];

                        static #WSDF_VARIANT_SUBTREE_LABELS: [wsdf::SubtreeLabel; #nr_variants]
                            = [#(#variant_subtree_labels,)*];

                        #(#funcs)*

                        let #WSDF_OFFSET = match #WSDF_DISPATCH {
                            wsdf::VariantDispatch::None => unreachable!(), // @todo: handle this panic
                            wsdf::VariantDispatch::Index(#WSDF_VARIANT_IDX) => {
                                #handle_dispatch_idx
                            }
                        };

                        #WSDF_OFFSET
                    }
                }
            }
        }
    }

    pub(crate) fn registration_fn(&self) -> syn::ItemFn {
        let register_fields = match self {
            DataRoot::Struct { data, .. } => data.registration_instructions(self),
            DataRoot::Enum { variants, .. } => {
                let instructions = variants
                    .iter()
                    .map(|variant| variant.data.registration_instructions(self));
                let variants_snake_cased = variants
                    .iter()
                    .map(|variant| variant.data.ident().to_wsdf_snake_case());

                instructions
                    .zip(variants_snake_cased)
                    .map(|(register_variant_fields, snake_cased)| {
                        quote! {
                            {
                                // Note the explicit block here. This prevents the original
                                // WSDF_PREFIX from being overwritten, since the other variants
                                // would need it also.
                                let #WSDF_PREFIX = #WSDF_PREFIX.to_owned() + "." + #snake_cased;
                                #register_variant_fields
                            }
                        }
                    })
                    .streamify()
            }
        };

        let self_ident = self.ident();

        parse_quote! {
            fn register(#REGISTRATION_PARAMS) {
                let mut #WSDF_HFS: Vec<wsdf::epan_sys::hf_register_info> = Vec::new();

                #register_fields

                let #WSDF_HFS = std::boxed::Box::leak(#WSDF_HFS.into_boxed_slice());
                unsafe {
                    wsdf::epan_sys::proto_register_field_array(
                        #WSDF_PROTO_ID,
                        #WSDF_HFS.as_mut_ptr() as *mut wsdf::epan_sys::hf_register_info,
                        #WSDF_HFS.len() as std::ffi::c_int,
                    );
                }

                *<#self_ident as wsdf::ProtocolField>::proto_id() = #WSDF_PROTO_ID; // "cache" the protocol ID
            }
        }
    }

    fn ident(&self) -> &syn::Ident {
        use DataRoot::*;
        use DataTerminal::*;

        match self {
            Struct { data, .. } => match data {
                UnitTuple { ident, .. } | DataClass { ident, .. } => ident,
            },
            Enum { ident, .. } => ident,
        }
    }

    /// Returns an expression which evaluates to the ETT for this type.
    fn ett_expr(&self) -> syn::Expr {
        let ident = self.ident();
        // We basically just call the ProtocolField::ett() function...
        parse_quote! { <#ident as wsdf::ProtocolField>::ett() }
    }

    fn proto_id(&self) -> syn::Expr {
        let ident = self.ident();
        parse_quote! { <#ident as wsdf::ProtocolField>::proto_id() }
    }

    fn is_unit_tuple(&self) -> bool {
        matches!(
            self,
            DataRoot::Struct {
                data: DataTerminal::UnitTuple { .. },
                ..
            }
        )
    }

    fn is_top_level(&self) -> bool {
        use DataRoot::*;

        match self {
            Struct { is_top_level, .. } => *is_top_level,
            // Enums are not allowed at the top level.
            Enum { .. } => false,
        }
    }
}

impl<'a> DataRoot<'a> {
    pub(crate) fn from_input(input: &'a syn::DeriveInput, is_top_level: bool) -> syn::Result<Self> {
        let opts = init_options::<ProtocolFieldOptions>(&input.attrs)?;
        let cfg = DataRootConfig {
            pre_dissect: opts.pre_dissect,
            post_dissect: opts.post_dissect,
        };

        match &input.data {
            syn::Data::Struct(data) => Ok(DataRoot::Struct {
                is_top_level,
                data: DataTerminal::from_struct(&input.ident, data, &input.attrs)?,
                cfg,
            }),

            syn::Data::Enum(data) => {
                if data.variants.is_empty() {
                    return make_err(&input.ident, "expected at least one variant");
                }

                let mut variants = Vec::new();

                for variant in &data.variants {
                    let data = DataTerminal::from_variant(variant)?;
                    variants.push(EnumVariant { data });
                }

                Ok(DataRoot::Enum {
                    ident: &input.ident,
                    variants,
                    cfg,
                })
            }
            syn::Data::Union(u) => make_err(
                &u.union_token,
                "unions cannot derive Protocol or ProtocolField",
            ),
        }
    }
}

impl<'a> DataTerminal<'a> {
    fn from_variant(variant: &'a syn::Variant) -> syn::Result<Self> {
        let opts = init_options::<VariantOptions>(&variant.attrs)?;
        match &variant.fields {
            syn::Fields::Named(data) => Self::from_named_fields(&variant.ident, &data.named, opts),
            syn::Fields::Unnamed(data) => {
                Self::from_unit_tuple(&variant.ident, &data.unnamed, opts)
            }
            // We don't really expect Unit types to be used. In any case, they are equivalent to
            // a regular variant with zero fields.
            syn::Fields::Unit => Self::from_named_fields(&variant.ident, &[], opts),
        }
    }

    fn from_struct(
        ident: &'a syn::Ident,
        data: &'a syn::DataStruct,
        _attrs: &'a [syn::Attribute],
    ) -> syn::Result<Self> {
        match &data.fields {
            syn::Fields::Named(data) => {
                Self::from_named_fields(ident, &data.named, VariantOptions::default())
            }
            syn::Fields::Unnamed(data) => {
                Self::from_unit_tuple(ident, &data.unnamed, VariantOptions::default())
            }
            syn::Fields::Unit => {
                make_err(&data.fields, "expected struct to have at least one field")
            }
        }
    }

    fn from_named_fields(
        ident: &'a syn::Ident,
        fields: impl IntoIterator<Item = &'a syn::Field>,
        opts: VariantOptions,
    ) -> syn::Result<Self> {
        let mut proto_fields = Vec::new();
        for field in fields {
            proto_fields.push(ProtoField::from_field(field)?);
        }

        check_fields(&mut proto_fields)?;

        Ok(DataTerminal::DataClass {
            ident,
            rename: opts.rename,
            fields: proto_fields,
        })
    }

    fn from_unit_tuple(
        ident: &'a syn::Ident,
        fields: &'a Punctuated<syn::Field, syn::Token![,]>,
        opts: VariantOptions,
    ) -> syn::Result<Self> {
        if fields.len() != 1 {
            return make_err(fields, "expected exactly one element in tuple type");
        }

        let field = fields.last().unwrap(); // safe to unwrap
        let mut inner = [ProtoField::from_field_with_ident(field, ident)?];

        check_fields(&mut inner)?;

        Ok(DataTerminal::UnitTuple {
            ident,
            rename: opts.rename,
            inner: inner[0].clone(),
        })
    }

    fn ident(&self) -> &'a syn::Ident {
        use DataTerminal::*;
        match self {
            UnitTuple { ident, .. } | DataClass { ident, .. } => ident,
        }
    }

    fn dissection_instructions(&self, parent: &DataRoot) -> proc_macro2::TokenStream {
        use DataTerminal::*;

        match self {
            UnitTuple { inner, .. } => {
                let dissect_field = inner.dissection_instructions(parent);

                // Here, we pass the prefix straight through without appending anything. No
                // particular reason for this, except that it makes the abbreviations (used in
                // filters) nicer in wireshark. For example,
                //
                // ```
                // #[derive(Protocol)]
                // enum Foo { Bar(Bar) };
                // #[derive(ProtocolField)]
                // struct Bar { baz: u8 };
                // ```
                //
                // would register foo.bar.baz instead of foo.bar.bar.baz.
                quote! {
                    let #WSDF_PREFIX_NEXT = #WSDF_PREFIX.to_owned();
                    #dissect_field
                }
            }
            DataClass { fields, .. } => {
                let dissect_fields = fields
                    .iter()
                    .map(|field| field.dissection_instructions(parent));
                let fields_snake_cased =
                    fields.iter().map(|field| field.ident.to_wsdf_snake_case());
                dissect_fields
                    .zip(fields_snake_cased)
                    .map(|(dissect_field, snake_cased)| {
                        // It is important that we do not enclose this code into its own block,
                        // since some fields may have been emitted during dissection and we may
                        // need to use it later, e.g. a length field which will be used later
                        // for a Vec.
                        //
                        // If it was in its own block, the variable storing the field's value
                        // would be scoped to the block and can't be accessed later!
                        quote! {
                            let #WSDF_PREFIX_NEXT = #WSDF_PREFIX.to_owned() + "." + #snake_cased;
                            #dissect_field
                        }
                    })
                    .streamify()
            }
        }
    }

    fn registration_instructions(&self, parent: &DataRoot) -> proc_macro2::TokenStream {
        use DataTerminal::*;
        match self {
            UnitTuple { inner, rename, .. } => {
                let register_field = inner.registration_instructions(parent, rename);
                quote! {
                    let #WSDF_PREFIX_NEXT = #WSDF_PREFIX.to_owned();
                    #register_field
                }
            }
            DataClass { fields, .. } => {
                let register_fields = fields
                    .iter()
                    .map(|field| field.registration_instructions(parent, &None));
                let fields_snake_cased =
                    fields.iter().map(|field| field.ident.to_wsdf_snake_case());
                register_fields
                    .zip(fields_snake_cased)
                    .map(|(register_field, snake_cased)| {
                        quote! {
                            let #WSDF_PREFIX_NEXT = #WSDF_PREFIX.to_owned() + "." + #snake_cased;
                            #register_field
                        }
                    })
                    .streamify()
            }
        }
    }
}

/// Checks and processes fields to see if there is any invalid option. Not exhaustive.
///
/// We need a mutable slice because we may also initialize or adjust some attributes on the fields.
fn check_fields(fields: &mut [ProtoField]) -> syn::Result<()> {
    /// Checks that all length providers are valid.
    fn check_len_providers(fields: &mut [ProtoField]) -> syn::Result<()> {
        let mut len_providers = HashSet::new();

        for field in &*fields {
            if let Some(ident) = field.typ.get_len_field() {
                len_providers.insert(ident.clone());
            }
        }

        for field in fields {
            if len_providers.contains(field.ident) {
                use PrimitiveType::*;

                match field.typ.as_mut() {
                    DataType::Primitive(data) => match data.typ {
                        U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 => data.is_used_later = true,
                        ByteArray { .. } => {
                            return make_err(
                                &field.field.ident,
                                "this field cannot be used to indicate length",
                            )
                        }
                    },
                    DataType::Collection(_) => {
                        return make_err(
                            &field.field.ident,
                            "this field cannot be used to indicate length",
                        )
                    }
                }
            }
        }

        Ok(())
    }

    fn check_dispatch_providers(fields: &mut [ProtoField]) -> syn::Result<()> {
        let mut dispatch_providers = HashSet::new();

        for field in &*fields {
            if let DataType::Collection(data) = field.typ.as_ref() {
                // The type could be an enum or a list of enums. We'll handle both cases here.
                let dispatch = match &data.typ {
                    CollectionType::List { elem, .. } => match elem.as_ref() {
                        DataType::Collection(data) => match &data.typ {
                            CollectionType::Enum { dispatch, .. } => dispatch,
                            _ => continue,
                        },
                        _ => continue,
                    },
                    CollectionType::Enum { dispatch, .. } => dispatch,
                    _ => continue,
                };
                dispatch_providers.insert(dispatch.clone());
            }
        }

        for field in fields {
            if dispatch_providers.contains(field.ident) {
                match field.typ.as_mut() {
                    DataType::Primitive(data) => data.is_used_later = true,
                    DataType::Collection(_) => {
                        return make_err(
                            &field.field.ident,
                            "this field cannot be used to dispatch enums",
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks, for fields which are to be subdissected, whether the subdissector is valid. Some
    /// subdissectors could be invalid, e.g., something like "udp.port" but you pass it a string
    /// field instead of a uint.
    fn check_subdissectors(fields: &mut [ProtoField]) -> syn::Result<()> {
        // Record all the fields we have seen thus far. It would be an error if the subdissector
        // needs to reference some field which is in the future.
        let mut seen: HashMap<&syn::Ident, &mut Primitive> = HashMap::new();

        for field in &mut *fields {
            use PrimitiveType::*;

            match field.typ.get_subdissector_mut() {
                None => {
                    if let DataType::Primitive(data) = field.typ.as_mut() {
                        seen.insert(field.ident, data);
                    }
                }
                Some(subdissector) => {
                    if let Subdissector::Table {
                        fields: target_fields,
                        typ: ref mut target_typ,
                        ..
                    } = subdissector
                    {
                        for target_field in target_fields {
                            use SubdissectorTableType::*;

                            let field_data = match seen.get_mut(target_field) {
                                None => return make_err(field.field, "invalid subdissector call"),
                                Some(field_data) => field_data,
                            };
                            let ws_type = field_data.ws_type();
                            let ws_display = field_data.ws_display();

                            field_data.is_used_later = true;

                            match &field_data.typ {
                            U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 => match target_typ {
                                Uint { .. } => (),
                                Str => {
                                    return make_err(
                                        field.field,
                                        "conflicting subdissector table types (expected uint, found string)",
                                    )
                                }
                                Unknown => *target_typ = Uint {
                                    ws_type: Box::new(ws_type),
                                    ws_display: Box::new(ws_display),
                                },
                            },
                            ByteArray { .. } => match target_typ {
                                Uint { .. } => {
                                    return make_err(
                                        field.field,
                                        "conflicting subdissector table types (expected string, found uint)",
                                    )
                                }
                                Str => (),
                                Unknown => *target_typ = Str,
                            },
                        }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    check_len_providers(fields)?;
    check_dispatch_providers(fields)?;
    check_subdissectors(fields)?;

    Ok(())
}

impl DataTerminal<'_> {
    fn renamed(&self) -> &Option<String> {
        match self {
            DataTerminal::UnitTuple { rename, .. } | DataTerminal::DataClass { rename, .. } => {
                rename
            }
        }
    }

    /// A custom name for the subtree root in Wireshark's UI.
    fn subtree_label(&self) -> syn::Expr {
        match self.renamed() {
            None => parse_quote! { wsdf::SubtreeLabel::null() },
            Some(name) => {
                let name: syn::Expr = cstr!(name);
                parse_quote! { wsdf::SubtreeLabel::new(#name) }
            }
        }
    }

    /// For dissection. Updates the WSDF_PARENT_NODE variable, if needed.
    fn update_parent_node(&self, root: &DataRoot) -> Option<syn::Stmt> {
        match self {
            // Unit tuple types are meant to be "transparent". The enclosed type will be
            // responsible for producing a subtree if needed.
            DataTerminal::UnitTuple { .. } => None,
            DataTerminal::DataClass { rename, .. } => {
                // Structs are expected to create their own subtree, i.e. a plain text node with
                // child nodes for its fields. The caller of the struct's `dissect` function may
                // pass in a description for the text node, or it may not.  Thus we generate a
                // default one from the struct's identifier.
                let default_label = rename
                    .clone()
                    .unwrap_or_else(|| self.ident().to_wsdf_title_case());
                let default_label_cstr: syn::Expr = cstr!(default_label);
                let label_cstr = parse_quote! {
                    #WSDF_SUBTREE_LABEL.unwrap_or(#default_label_cstr)
                };

                let create_subtree = Self::create_proto_subtree(root, &label_cstr);

                Some(parse_quote! {
                    // Override the parent node.
                    let #WSDF_PARENT_NODE = #create_subtree;
                })
            }
        }
    }

    fn create_proto_subtree(root: &DataRoot, label_cstr: &syn::Expr) -> proc_macro2::TokenStream {
        // The way we add a node to the tree differs slightly based on whether the "dataclass"
        // is at the top level (representing the entire protocol). This is purely for cosmetic
        // reasons!
        let ett_expr = root.ett_expr();
        if root.is_top_level() {
            let proto_id = root.proto_id();
            quote! {
                unsafe {
                    let ti = wsdf::epan_sys::proto_tree_add_item(
                        #WSDF_PARENT_NODE,
                        *#proto_id,
                        #WSDF_TVB,
                        #WSDF_START,
                        -1, // set to -1 for now
                        wsdf::epan_sys::ENC_NA,
                    );
                    wsdf::epan_sys::proto_item_set_text(
                        ti,
                        #label_cstr,
                    );
                    wsdf::epan_sys::proto_item_add_subtree(ti, #ett_expr)
                }
            }
        } else {
            quote! {
                unsafe {
                    wsdf::epan_sys::proto_tree_add_subtree(
                        #WSDF_PARENT_NODE,
                        #WSDF_TVB,
                        #WSDF_START,
                        -1,
                        #ett_expr,
                        std::ptr::null_mut(),
                        #label_cstr,
                    )
                }
            }
        }
    }

    fn call_hooks(hooks: &[syn::Path]) -> Option<proc_macro2::TokenStream> {
        if hooks.is_empty() {
            return None;
        }
        let create_ctx = DataType::create_ctx_with_field(&parse_quote! { () });
        let calls = hooks.iter().map(|hook| {
            quote! { wsdf::tap::handle_tap(&#WSDF_TAP_CTX, #hook); }
        });
        Some(quote! {
            #create_ctx
            #(#calls)*
        })
    }

    /// Creates the function to dissect this type. Each `DataTerminal` corresponds to one
    /// dissection function.
    fn dissection_fn(
        &self,
        root: &DataRoot,
        fn_ident: &syn::Ident,
        pre_dissect: &[syn::Path],
        post_dissect: &[syn::Path],
    ) -> syn::ItemFn {
        let pre_dissect = Self::call_hooks(pre_dissect);
        let post_dissect = Self::call_hooks(post_dissect);

        let update_parent = self.update_parent_node(root).streamify();

        let dissect_stuff = self.dissection_instructions(root); // the actual code which dissects stuff

        // Recall that we create new subtrees with size -1, because we may or may not know the
        // size of all its fields. After dissecting all the fields, the WSDF_OFFSET variable
        // effectively contains the size of the subtree.
        //
        // Wireshark exposes the `proto_item_set_len` function for manually configuring the size
        // of a proto_item.
        let update_subtree_size = quote! {
            unsafe {
                wsdf::epan_sys::proto_item_set_len(#WSDF_PARENT_NODE, #WSDF_OFFSET);
            }
        };

        parse_quote! {
            #[allow(clippy::too_many_arguments, clippy::ptr_arg, clippy::int_plus_one)]
            fn #fn_ident<'a>(#DISSECTION_PARAMS) -> std::ffi::c_int {
                #update_parent
                let mut #WSDF_OFFSET = 0;
                let mut fields_local = wsdf::FieldsStore::default();

                #pre_dissect

                #dissect_stuff

                #update_subtree_size

                #post_dissect

                #WSDF_OFFSET // return the no. of bytes consumed
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProtoField<'a> {
    ident: &'a syn::Ident,
    /// A custom name for this field.
    rename: Option<String>,

    field: &'a syn::Field,
    typ: Box<DataType>,
}

impl<'a> ProtoField<'a> {
    /// Constructs a `ProtoField` from a named field.
    fn from_field(field: &'a syn::Field) -> syn::Result<Self> {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.ident.span(), "expected field to be named"))?;
        Self::from_field_with_ident(field, ident)
    }

    /// Constructs a `ProtoField` from a field which may not be named. An explicitly identifier
    /// is required.
    fn from_field_with_ident(field: &'a syn::Field, ident: &'a syn::Ident) -> syn::Result<Self> {
        let options = init_options::<FieldOptions>(&field.attrs)?;
        let typ = DataType::from_syn_type(&field.ty, &options)?;
        Ok(Self {
            ident,
            rename: options.rename,
            field,
            typ: Box::new(typ),
        })
    }
}

impl ProtoField<'_> {
    fn dissection_instructions(&self, root: &DataRoot) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.ident.to_wsdf_snake_case());

        let retrieve_hf = self.typ.retrieve_hf(root.ident());
        let emit_expr = self.typ.emit_field(&field_ident);
        let add_to_fields_store = self.typ.add_to_fields_store(&field_ident);
        let create_ctx = self.typ.create_ctx(&field_ident);
        let call_taps = self.typ.call_taps().streamify();
        let add_to_tree = self
            .typ
            .add_to_tree(&field_ident, &self.name(), root.ident());

        quote! {
            #retrieve_hf
            #emit_expr
            #add_to_fields_store
            #create_ctx
            #call_taps
            #add_to_tree
        }
    }

    fn registration_instructions(
        &self,
        root: &DataRoot,
        field_name: &Option<String>,
    ) -> proc_macro2::TokenStream {
        let docs = get_docs(&self.field.attrs);
        let field_name = field_name.clone().unwrap_or_else(|| self.name());

        let call_subroutine = self.typ.register_user_type(&field_name, &docs);
        let create_hf = self
            .typ
            .create_hf(root.is_unit_tuple(), root.ident(), &field_name, &docs);
        let reg_subdissector = self.typ.register_subdissector(root.ident());

        quote! {
            #call_subroutine
            #create_hf
            #reg_subdissector
        }
    }

    fn name(&self) -> String {
        self.rename
            .clone()
            .unwrap_or_else(|| self.ident.to_wsdf_title_case())
    }
}

const WSDF_VARIANT_NAMES: IdentHelper = IdentHelper("__WSDF_VARIANT_NAMES");
const WSDF_VARIANT_DISSECT_FNS: IdentHelper = IdentHelper("__WSDF_VARIANT_DISSECT_FNS");
const WSDF_VARIANT_SUBTREE_LABELS: IdentHelper = IdentHelper("__WSDF_VARIANT_SUBTREE_LABELS");
const WSDF_VARIANT_IDX: IdentHelper = IdentHelper("__wsdf_variant_idx");

/// The "innards" of a struct-like object we care about. This is either a unit tuple or a regular
/// thing with named fields.
///
/// This applies to structs of course, but also enum variants.
pub(crate) enum StructInnards {
    UnitTuple(UnitTuple),
    NamedFields { fields: Vec<NamedField> },
}

pub(crate) struct UnitTuple(pub(crate) FieldMeta);

#[derive(Clone)]
pub(crate) struct NamedField {
    ident: syn::Ident,
    meta: FieldMeta,
}

/// Field metadata.
#[derive(Clone)]
pub(crate) struct FieldMeta {
    ty: syn::Type,
    docs: Option<String>,
    options: FieldOptions,

    /// For fields which are given to subdissectors, what the key type is. For Decode As
    /// dissectors, this would be `()`, otherwise it could be, e.g. a u16 for "udp.port".
    ///
    /// If the field is not to be subdissected, should be None.
    subdissector_key_type: Option<syn::Type>,
}

impl StructInnards {
    pub(crate) fn from_fields(fields: &syn::Fields) -> syn::Result<Self> {
        match fields {
            syn::Fields::Named(fields) => Self::from_fields_named(fields),
            syn::Fields::Unnamed(fields) => Self::from_fields_unnamed(fields),
            syn::Fields::Unit => Ok(StructInnards::UnitTuple(UnitTuple(FieldMeta {
                ty: parse_quote! { () },
                docs: None,
                options: FieldOptions::default(),
                subdissector_key_type: None,
            }))),
        }
    }

    fn from_fields_named(fields: &syn::FieldsNamed) -> syn::Result<Self> {
        let mut named_fields = Vec::new();
        for field in &fields.named {
            let ident = field.ident.clone().unwrap(); // safe since the fields are named
            let options = init_options::<FieldOptions>(&field.attrs)?;
            let docs = get_docs(&field.attrs);
            let meta = FieldMeta {
                ty: field.ty.clone(),
                docs,
                options,
                subdissector_key_type: None,
            };
            named_fields.push(NamedField { ident, meta });
        }
        Ok(StructInnards::NamedFields {
            fields: named_fields,
        })
    }

    fn from_fields_unnamed(fields: &syn::FieldsUnnamed) -> syn::Result<Self> {
        if fields.unnamed.len() != 1 {
            return make_err(fields, "expected only one field in tuple");
        }
        let field = fields.unnamed.last().unwrap(); // safe since we checked there's exactly one
        let options = init_options::<FieldOptions>(&field.attrs)?;
        let docs = get_docs(&field.attrs);
        Ok(StructInnards::UnitTuple(UnitTuple(FieldMeta {
            ty: field.ty.clone(),
            docs,
            options,
            subdissector_key_type: None,
        })))
    }

    fn register_fields(&self) -> Vec<syn::Stmt> {
        match self {
            StructInnards::UnitTuple(unit) => {
                let decl_args = unit.decl_register_args();
                let call_register_func = unit.call_inner_register_func();
                parse_quote! {
                    #decl_args
                    #call_register_func
                }
            }
            StructInnards::NamedFields { fields } => {
                let fields = assign_subdissector_key_types(fields);
                fields
                    .iter()
                    .flat_map(NamedField::registration_steps)
                    .collect()
            }
        }
    }

    fn dissect_fields(&self) -> Vec<syn::Stmt> {
        match self {
            StructInnards::UnitTuple(unit) => unit.dissect_field(),
            StructInnards::NamedFields { fields } => {
                let plans = get_field_dissection_plans(fields);
                fields
                    .iter()
                    .zip(plans)
                    .flat_map(|(field, plan)| field.dissection_steps(&plan))
                    .collect()
            }
        }
    }

    pub(crate) fn add_to_tree_fn(&self, dissect_options: &ProtocolFieldOptions) -> syn::ItemFn {
        let dissect_fields = self.dissect_fields();
        let fn_contents: Vec<syn::Stmt> = match self {
            StructInnards::UnitTuple(_) => parse_quote! {
                #(#dissect_fields)*
            },
            StructInnards::NamedFields { .. } => parse_quote! {
                let parent = args.add_subtree();
                #(#dissect_fields)*

                // When the subtree was created above, its size should have been uninitialized. We
                // set it manually here, now that all fields have been dissected and we know its
                // size.
                unsafe {
                    wsdf::epan_sys::proto_item_set_len(parent, (offset - args.offset) as _);
                }
            },
        };
        let pre_dissect = pre_post_dissect(&dissect_options.pre_dissect);
        let post_dissect = pre_post_dissect(&dissect_options.post_dissect);
        parse_quote! {
            fn add_to_tree(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                // Some type-wide declarations.
                let mut fields_local = wsdf::FieldsStore::default();
                let offset = args.offset;
                #(#pre_dissect)* // this should appear after offset is declared
                #(#fn_contents)*
                #(#post_dissect)*
                offset - args.offset // return the number of bytes dissected
            }
        }
    }

    pub(crate) fn size_fn(&self) -> syn::ItemFn {
        let fn_contents: Vec<syn::Stmt> = match self {
            // We use a trick here. We create the field dissection plan as per usual, but then
            // modify its add_strategy to be hidden. This has the same effect as simply querying
            // the field's size.
            StructInnards::UnitTuple(unit) => {
                let mut plan = FieldDissectionPlan::from_unit_tuple(unit);
                plan.add_strategy = AddStrategy::Hidden;
                unit.dissect_field_with_plan(&plan)
            }
            StructInnards::NamedFields { fields } => {
                let mut plans = get_field_dissection_plans(fields);
                for plan in &mut plans {
                    plan.add_strategy = AddStrategy::Hidden;
                }
                fields
                    .iter()
                    .zip(plans)
                    .flat_map(|(field, plan)| field.dissection_steps(&plan))
                    .collect()
            }
        };
        parse_quote! {
            fn size(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                let offset = args.offset;
                let parent = args.parent; // doesn't matter where it points to since we're not
                                          // adding to the tree
                #(#fn_contents)*
                offset - args.offset
            }
        }
    }

    pub(crate) fn register_fn(&self) -> syn::ItemFn {
        let register_fields = self.register_fields();
        let fn_contents: Vec<syn::Stmt> = match self {
            StructInnards::UnitTuple(_) => register_fields,
            StructInnards::NamedFields { .. } => parse_quote! {
                // A group of named fields must be hung together under a new subtree. So we'll need
                // to create it here (both the ETT and HF).
                let _ = ws_indices.ett.get_or_create_ett(args);
                let _ = ws_indices.hf.get_or_create_text_node(args);

                #(#register_fields)*
            },
        };
        parse_quote! {
            fn register(args: &wsdf::RegisterArgs, ws_indices: &mut wsdf::WsIndices) {
                #(#fn_contents)*
            }
        }
    }
}

impl UnitTuple {
    fn decl_register_args(&self) -> syn::Stmt {
        let blurb = self.blurb_expr();
        let ws_type = self.0.ws_type_as_expr();
        let ws_display = self.0.ws_display_as_expr();

        parse_quote! {
            let args_next = wsdf::RegisterArgs {
                proto_id: args.proto_id,
                name: args.name,
                prefix: args.prefix,
                blurb: #blurb,
                ws_type: #ws_type,
                ws_display: #ws_display,
            };
        }
    }

    fn decl_dissector_args(&self) -> syn::Stmt {
        let ws_enc = self.0.ws_enc_as_expr();
        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: args.prefix,
                prefix_local: args.prefix_local,
                offset: args.offset,
                parent: args.parent,
                variant: std::option::Option::None,
                list_len: std::option::Option::None,
                ws_enc: #ws_enc,
            };
        }
    }

    fn blurb_expr(&self) -> syn::Expr {
        // For unit tuples, we would like to take the blurb from its "parent" field.
        let blurb_cstr = self.0.blurb_cstr();
        parse_quote! {
            if !args.blurb.is_null() { args.blurb }
            else { #blurb_cstr }
        }
    }

    fn call_inner_register_func(&self) -> syn::Stmt {
        self.0.call_register_func()
    }

    fn dissect_field(&self) -> Vec<syn::Stmt> {
        let plan = FieldDissectionPlan::from_unit_tuple(self);
        self.dissect_field_with_plan(&plan)
    }

    fn dissect_field_with_plan(&self, plan: &FieldDissectionPlan) -> Vec<syn::Stmt> {
        let decl_args_next = self.decl_dissector_args();
        let var_name = format_ident!("__inner_value"); // just a random symbol to store the inner
                                                       // field's value, if it is emitted
        plan.dissection_steps(&decl_args_next, &var_name)
    }
}

impl NamedField {
    fn registration_steps(&self) -> Vec<syn::Stmt> {
        let ident_str = self.ident.to_string();
        let decl_prefix: syn::Stmt = parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #ident_str;
        };

        let name = self
            .meta
            .options
            .rename
            .clone()
            .unwrap_or(self.ident.to_wsdf_title_case());
        let name: syn::Expr = cstr!(name);
        let decl_args = self
            .meta
            .decl_register_args(&name, &parse_quote!(&prefix_next));

        let call_register_func = self.meta.call_register_func();

        parse_quote! {
            #decl_prefix
            #decl_args
            #call_register_func
        }
    }

    fn dissection_steps(&self, plan: &FieldDissectionPlan) -> Vec<syn::Stmt> {
        let decl_prefix_next = self.decl_prefix_next();
        let decl_args_next = self.decl_dissector_args();

        // By convention, when a field is emitted, we'll store it in a variable named like so -
        // just prepend two underscores.
        let var_name = format_ident!("__{}", self.ident);

        let steps = plan.dissection_steps(&decl_args_next, &var_name);

        parse_quote! {
            #decl_prefix_next
            #(#steps)*
        }
    }

    fn decl_prefix_next(&self) -> syn::Stmt {
        let field_name = self.ident.to_string();
        parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #field_name;
        }
    }

    fn decl_dissector_args(&self) -> syn::Stmt {
        let variant = self.meta.get_variant_as_expr();
        let list_len = self.meta.size_hint_as_expr();
        let ws_enc = self.meta.ws_enc_as_expr();
        let field_ident = self.ident.to_string();

        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: &prefix_next,
                prefix_local: #field_ident,
                offset,
                parent,
                variant: #variant,
                list_len: #list_len,
                ws_enc: #ws_enc,
            };
        }
    }
}

impl FieldMeta {
    fn blurb_cstr(&self) -> syn::Expr {
        match &self.docs {
            Some(docs) => cstr!(docs),
            None => parse_quote! { std::ptr::null() },
        }
    }

    fn ws_type_as_expr(&self) -> syn::Expr {
        self.options.ws_type_as_expr()
    }

    fn ws_display_as_expr(&self) -> syn::Expr {
        self.options.ws_display_as_expr()
    }

    fn ws_enc_as_expr(&self) -> syn::Expr {
        self.options.ws_enc_as_expr()
    }

    fn size_hint_as_expr(&self) -> syn::Expr {
        self.options.size_hint_as_expr()
    }

    fn get_variant_as_expr(&self) -> syn::Expr {
        self.options.get_variant_as_expr()
    }

    fn maybe_bytes(&self) -> syn::Type {
        self.options.maybe_bytes()
    }

    fn call_register_func(&self) -> syn::Stmt {
        let field_ty = &self.ty;
        // Most fields will just be registered as per normal (recursively via ::register). But some
        // fields are to be subdissected.
        //
        // In which case we'll have to register the subdissector instead.
        match &self.options.subdissector {
            None => {
                let maybe_bytes = self.maybe_bytes();
                parse_quote! {
                    <#field_ty as wsdf::Dissect<'tvb, #maybe_bytes>>::register(&args_next, ws_indices);
                }
            }
            Some(Subdissector::DecodeAs(table_name)) => parse_quote! {
                <() as wsdf::SubdissectorKey>::create_table(args_next.proto_id, #table_name, ws_indices.dtable);
            },
            Some(Subdissector::Table { table_name, .. }) => {
                debug_assert!(self.subdissector_key_type.is_some());
                let key_type = self.subdissector_key_type.as_ref().unwrap();
                parse_quote! {
                    <#key_type as wsdf::SubdissectorKey>::create_table(args.proto_id, #table_name, ws_indices.dtable);
                }
            }
        }
    }

    fn decl_register_args(&self, name: &syn::Expr, prefix: &syn::Expr) -> syn::Stmt {
        let blurb = self.blurb_cstr();
        let ws_type = self.ws_type_as_expr();
        let ws_display = self.ws_display_as_expr();
        parse_quote! {
            let args_next = wsdf::RegisterArgs {
                proto_id: args.proto_id,
                name: #name,
                prefix: #prefix,
                blurb: #blurb,
                ws_type: #ws_type,
                ws_display: #ws_display,
            };
        }
    }
}

impl FieldOptions {
    fn ws_type_as_expr(&self) -> syn::Expr {
        match &self.ws_type {
            Some(ty) => {
                let ws_type = format_ws_type(ty);
                parse_quote! { std::option::Option::Some(#ws_type) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn ws_display_as_expr(&self) -> syn::Expr {
        match &self.ws_display {
            Some(display) => parse_quote! { std::option::Option::Some(#display) },
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn ws_enc_as_expr(&self) -> syn::Expr {
        match &self.ws_enc {
            Some(enc) => {
                let ws_enc = format_ws_enc(enc);
                parse_quote! { std::option::Option::Some(#ws_enc) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn size_hint_as_expr(&self) -> syn::Expr {
        match &self.size_hint {
            Some(size_hint) => {
                let field_name = format_ident!("__{size_hint}");
                parse_quote! { std::option::Option::Some(#field_name as usize) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn get_variant_as_expr(&self) -> syn::Expr {
        match &self.get_variant {
            Some(get_variant) => parse_quote! {
                // This ugly bit is just to get around some lifetime issues in the final code. We
                // create a temporary context holding a field of `()` and pass that into context
                // handler.
                std::option::Option::Some(
                    wsdf::tap::handle_get_variant(&wsdf::tap::Context {
                        field: (),
                        fields,
                        fields_local: &fields_local,
                        pinfo: args.pinfo,
                        packet: args.data,
                        offset,
                    },
                    #get_variant,
                ))
            },
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn maybe_bytes(&self) -> syn::Type {
        match self.bytes {
            Some(true) => parse_quote! { [u8] },
            Some(false) | None => parse_quote! { () },
        }
    }

    fn requires_ctx(&self) -> bool {
        !self.taps.is_empty()
            || self.consume_with.is_some()
            || self.decode_with.is_some()
            || self.get_variant.is_some()
    }
}

/// Contains all the information we need to generate the steps to dissect a field.
struct FieldDissectionPlan<'a> {
    emit: bool,
    save: bool,
    build_ctx: bool,
    taps: &'a [syn::Path],
    add_strategy: AddStrategy,

    meta: &'a FieldMeta,
}

/// How a field should be added to the protocol tree.
enum AddStrategy {
    Subdissect(Subdissector),
    DecodeWith(syn::Path),
    ConsumeWith(syn::Path),
    Hidden,

    /// Just add it plainly.
    Default,
}

impl AddStrategy {
    fn from_field_options(options: &FieldOptions) -> Self {
        // @todo: this should be validated earlier, or perhaps we should return an error here
        // instead of failing the assert.
        //
        // The idea is that at most one of these three should have been set.
        debug_assert!(matches!(
            (
                &options.decode_with,
                &options.consume_with,
                &options.subdissector
            ),
            (Some(_), None, None)
                | (None, Some(_), None)
                | (None, None, Some(_))
                | (None, None, None)
        ));

        if let Some(subd) = &options.subdissector {
            AddStrategy::Subdissect(subd.clone())
        } else if let Some(consume_fn) = &options.consume_with {
            AddStrategy::ConsumeWith(consume_fn.clone())
        } else if let Some(decode_fn) = &options.decode_with {
            AddStrategy::DecodeWith(decode_fn.clone())
        } else if let Some(true) = options.hidden {
            AddStrategy::Hidden
        } else {
            AddStrategy::Default
        }
    }
}

impl<'a> FieldDissectionPlan<'a> {
    fn from_unit_tuple(unit: &'a UnitTuple) -> Self {
        let options = &unit.0.options;
        let save = options.save == Some(true);
        let build_ctx = options.requires_ctx();
        let emit = build_ctx;
        let add_strategy = AddStrategy::from_field_options(options);

        Self {
            emit,
            save,
            build_ctx,
            taps: &options.taps,
            add_strategy,
            meta: &unit.0,
        }
    }
}

impl FieldDissectionPlan<'_> {
    fn dissection_steps(
        &self,
        decl_args_next: impl quote::ToTokens,
        field_var_name: &syn::Ident,
    ) -> Vec<syn::Stmt> {
        let emit_and_assign = self.emit_and_assign(field_var_name);
        let save_field = self.save_field();
        let build_tap_ctx = self.build_tap_ctx(field_var_name);
        let call_taps = self.call_taps();
        let exec_add_strategy = self.exec_add_strategy();

        parse_quote! {
            #decl_args_next
            #emit_and_assign
            #save_field
            #build_tap_ctx
            #(#call_taps)*
            #(#exec_add_strategy)*
        }
    }

    fn emit_and_assign(&self, var_name: &syn::Ident) -> Option<syn::Stmt> {
        if !self.emit {
            return None;
        }
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();
        Some(parse_quote! {
            let #var_name = <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::emit(&args_next);

        })
    }

    fn save_field(&self) -> Option<syn::Stmt> {
        if !self.save {
            return None;
        }
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();
        Some(parse_quote! {
            <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::save(&args_next, fields, &mut fields_local);
        })
    }

    fn build_tap_ctx(&self, field_value: impl quote::ToTokens) -> Option<syn::Stmt> {
        if !self.build_ctx {
            return None;
        }
        Some(parse_quote! {
            let ctx = wsdf::tap::Context {
                field: #field_value,
                fields,
                fields_local: &fields_local,
                pinfo: args.pinfo,
                packet: args.data,
                offset,
            };
        })
    }

    fn call_taps(&self) -> Vec<syn::Stmt> {
        self.taps
            .iter()
            .map(|tap_fn| {
                parse_quote! {
                    wsdf::tap::handle_tap(&ctx, #tap_fn);
                }
            })
            .collect()
    }

    fn exec_add_strategy(&self) -> Vec<syn::Stmt> {
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();

        match &self.add_strategy {
            AddStrategy::Subdissect(subd) => self.try_subdissector(subd),
            AddStrategy::ConsumeWith(consume_fn) => {
                parse_quote! {
                    let (n, s) = wsdf::tap::handle_consume_with(&ctx, #consume_fn);
                    <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::add_to_tree_format_value(&args_next, &s, n);
                    let offset = offset + n;
                }
            }
            AddStrategy::DecodeWith(decode_fn) => {
                parse_quote! {
                    let s = wsdf::tap::handle_decode_with(&ctx, #decode_fn);
                    let n = <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::size(&args_next, fields);
                    <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::add_to_tree_format_value(&args_next, &s, n);
                    let offset = offset + n;
                }
            }
            AddStrategy::Hidden => self.handle_hidden(),
            AddStrategy::Default => vec![parse_quote! {
                let offset = offset + <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::add_to_tree(&args_next, fields);
            }],
        }
    }

    fn handle_hidden(&self) -> Vec<syn::Stmt> {
        let maybe_bytes = self.meta.maybe_bytes();
        let ty = &self.meta.ty;

        if let Some(consume_fn) = &self.meta.options.consume_with {
            parse_quote! {
                // Assume that the context is already created.
                let (n, _) = wsdf::tap::handle_consume_with(&ctx, #consume_fn);
                let offset = offset + n;
            }
        } else if let Some(subd) = &self.meta.options.subdissector {
            self.try_subdissector_null_proto_root(subd)
        } else {
            parse_quote! {
                let offset = offset + <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::size(&args_next, fields);
            }
        }
    }

    fn try_subdissector(&self, subd: &Subdissector) -> Vec<syn::Stmt> {
        self.try_subdissector_with_proto_root(subd, &parse_quote!(args.proto_root))
    }

    fn try_subdissector_null_proto_root(&self, subd: &Subdissector) -> Vec<syn::Stmt> {
        self.try_subdissector_with_proto_root(subd, &parse_quote! { std::ptr::null_mut() })
    }

    fn try_subdissector_with_proto_root(
        &self,
        subd: &Subdissector,
        proto_root: &syn::Expr,
    ) -> Vec<syn::Stmt> {
        let ty = &self.meta.ty;

        let setup_tvb_next: syn::Stmt = parse_quote! {
            let tvb_next = <#ty as wsdf::Subdissect<'tvb>>::setup_tvb_next(&args_next);
        };
        let update_args_next: syn::Stmt = parse_quote! {
            let args_next = wsdf::DissectorArgs {
                tvb: tvb_next,
                proto_root: #proto_root,
                ..args_next
            };
        };
        let try_subdissector: Vec<syn::Stmt> = match subd {
            Subdissector::DecodeAs(table_name) => parse_quote! {
                let offset = offset + <#ty as wsdf::Subdissect<'tvb>>::try_subdissector(&args_next, #table_name, &());
            },
            Subdissector::Table {
                table_name, fields, ..
            } => {
                // Each field will be tried in sequence, and called only if none of the previous
                // one successfully dissected > 0 bytes.
                let try_fields = fields.iter().map(|field| -> syn::ExprIf {
                    let field_var_name = format_ident!("__{field}");
                    parse_quote! {
                        if nr_bytes_subdissected == 0 {
                            nr_bytes_subdissected
                                = <#ty as wsdf::Subdissect<'tvb>>::try_subdissector(
                                    &args_next,
                                    #table_name,
                                    &#field_var_name,
                                );
                        }
                    }
                });
                parse_quote! {
                    let mut nr_bytes_subdissected = 0;
                    #(#try_fields)*
                    if nr_bytes_subdissected == 0 {
                        nr_bytes_subdissected = args_next.call_data_dissector();
                    }
                    let offset = offset + nr_bytes_subdissected;
                }
            }
        };

        parse_quote! {
            #setup_tvb_next
            #update_args_next
            #(#try_subdissector)*
        }
    }
}

/// Scans a list of named fields and sets the `subdissector_key_type` on each.
fn assign_subdissector_key_types(fields: &[NamedField]) -> Vec<NamedField> {
    fields
        .iter()
        .map(|field| {
            let new_meta = match &field.meta.options.subdissector {
                Some(Subdissector::DecodeAs(_)) | None => FieldMeta {
                    subdissector_key_type: None,
                    ..field.meta.clone()
                },
                Some(Subdissector::Table { fields: keys, .. }) => {
                    // The idea here is to scan through the provided list of fields until the first
                    // one which matches one of the keys.
                    //
                    // @todo: ensure that all the keys can be found, and that their types match.
                    // This should be relatively easy once we remove the old code and use a better
                    // abstraction for Subdissector.
                    let mut new_meta = field.meta.clone();
                    for field in fields {
                        for key in keys {
                            if &field.ident == key {
                                new_meta.subdissector_key_type = Some(field.meta.ty.clone());
                            }
                        }
                    }
                    debug_assert!(new_meta.subdissector_key_type.is_some());
                    new_meta
                }
            };
            NamedField {
                meta: new_meta,
                ..field.clone()
            }
        })
        .collect()
}

fn get_field_dissection_plans(fields: &[NamedField]) -> Vec<FieldDissectionPlan> {
    let mut fields_to_emit = HashSet::new();
    for field in fields {
        let options = &field.meta.options;
        if options.requires_ctx() {
            fields_to_emit.insert(&field.ident);
        }
        if let Some(Subdissector::Table { fields, .. }) = &options.subdissector {
            for field in fields {
                fields_to_emit.insert(field);
            }
        }
        if let Some(dispatch_field) = &options.dispatch {
            fields_to_emit.insert(dispatch_field);
        }
        if let Some(len_field) = &options.size_hint {
            fields_to_emit.insert(len_field);
        }
    }

    fields
        .iter()
        .map(|field| {
            let options = &field.meta.options;

            let save = options.save == Some(true);
            let build_ctx = options.requires_ctx();
            let add_strategy = AddStrategy::from_field_options(options);

            FieldDissectionPlan {
                emit: fields_to_emit.contains(&field.ident),
                save,
                build_ctx,
                taps: &options.taps,
                add_strategy,
                meta: &field.meta,
            }
        })
        .collect()
}

pub(crate) struct Enum<'a> {
    ident: &'a syn::Ident,
    variants: Vec<Variant<'a>>,
}

struct Variant<'a> {
    data: &'a syn::Variant,
    options: VariantOptions,
}

impl Variant<'_> {
    fn ident(&self) -> &syn::Ident {
        &self.data.ident
    }

    fn ui_name(&self) -> String {
        self.options
            .rename
            .clone()
            .unwrap_or(self.ident().to_wsdf_title_case())
    }

    fn blurb_expr(&self) -> syn::Expr {
        let docs = get_docs(&self.data.attrs);
        match docs {
            Some(docs) => cstr!(docs),
            None => parse_quote! { std::ptr::null() },
        }
    }
}

impl<'a> Enum<'a> {
    pub(crate) fn new(
        ident: &'a syn::Ident,
        variants: &'a Punctuated<syn::Variant, syn::Token![,]>,
    ) -> syn::Result<Self> {
        let mut xs = Vec::with_capacity(variants.len());

        for variant in variants {
            let options = init_options::<VariantOptions>(&variant.attrs)?;
            xs.push(Variant {
                data: variant,
                options,
            });
        }

        Ok(Self {
            ident,
            variants: xs,
        })
    }

    pub(crate) fn ident(&self) -> &syn::Ident {
        self.ident
    }

    fn decl_prefix_next(&self, variant: &syn::Variant) -> syn::Stmt {
        let name_snake_case = variant.ident.to_wsdf_snake_case();

        parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #name_snake_case;
        }
    }

    fn decl_dissector_args(variant: &syn::Variant) -> syn::Stmt {
        let variant_snake_case = variant.ident.to_wsdf_snake_case();
        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: &prefix_next,
                prefix_local: #variant_snake_case,
                offset: args.offset,
                parent: args.parent,
                variant: std::option::Option::None,
                list_len: std::option::Option::None,
                ws_enc: std::option::Option::None,
            };
        }
    }

    pub(crate) fn add_to_tree_fn(&self) -> syn::ItemFn {
        let inner = self.match_and_call_on_variant(&parse_quote!(add_to_tree));
        parse_quote! {
            fn add_to_tree(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                #(#inner)*
            }
        }
    }

    pub(crate) fn size_fn(&self) -> syn::ItemFn {
        let inner = self.match_and_call_on_variant(&parse_quote!(size));
        parse_quote! {
            fn size(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                #(#inner)*
            }
        }
    }

    pub(crate) fn register_fn(&self) -> syn::ItemFn {
        let register_stmts = self.variants.iter().flat_map(|variant| -> Vec<syn::Stmt> {
            let name = variant.ui_name();
            let name_cstr: syn::Expr = cstr!(name);
            let blurb = variant.blurb_expr();
            let struct_name = format_ident!("__{}", variant.ident());

            let decl_prefix_next = self.decl_prefix_next(variant.data);
            let decl_args_next: syn::Stmt = parse_quote! {
                let args_next = wsdf::RegisterArgs {
                    proto_id: args.proto_id,
                    name: #name_cstr,
                    prefix: &prefix_next,
                    blurb: #blurb,
                    ws_type: std::option::Option::None,
                    ws_display: std::option::Option::None,
                };
            };

            parse_quote! {
                #decl_prefix_next
                #decl_args_next
                #struct_name::register(&args_next, ws_indices);
            }
        });
        parse_quote! {
            fn register(args: &wsdf::RegisterArgs, ws_indices: &mut wsdf::WsIndices) {
                #(#register_stmts)*
            }
        }
    }

    fn match_and_call_on_variant(&self, call: &syn::Path) -> Vec<syn::Stmt> {
        let arms = self.variants.iter().map(|variant| -> syn::Arm {
            let name = variant.ident().to_string();
            let decl_prefix_next = self.decl_prefix_next(variant.data);
            let setup_args_next = Self::decl_dissector_args(variant.data);
            let struct_name = format_ident!("__{}", variant.ident());

            parse_quote! {
                Some(#name) => {
                    #decl_prefix_next
                    #setup_args_next
                    #struct_name::#call(&args_next, fields)
                }
            }
        });
        let enum_ident_str = self.ident.to_string();
        parse_quote! {
            match args.variant {
                #(#arms)*
                Some(v) => panic!("unexpected variant {} of {}", v, #enum_ident_str),
                None => panic!("unable to determine variant of {}", #enum_ident_str),
            }
        }
    }
}

/// Generates the code for pre/post dissect hooks.
fn pre_post_dissect(funcs: &[syn::Path]) -> Vec<syn::Stmt> {
    if funcs.is_empty() {
        return Vec::new();
    }
    let decl_ctx: syn::Stmt = parse_quote! {
        let ctx = wsdf::tap::Context {
            field: (),
            fields,
            fields_local: &fields_local,
            pinfo: args.pinfo,
            packet: args.data,
            offset,
        };
    };
    let calls = funcs.iter().map(|func| -> syn::Stmt {
        parse_quote! {
            wsdf::tap::handle_tap(&ctx, #func);
        }
    });
    parse_quote! {
        #decl_ctx
        #(#calls)*
    }
}
