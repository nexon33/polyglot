use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0},
    combinator::{map, opt, recognize},
    multi::{many0, separated_list0},
    sequence::{delimited, pair, preceded, tuple},
    IResult, Parser,
};

#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceItem {
    Struct(StructDef),
    Enum(EnumDef),
    TypeAlias(String, Type),
    TypeDecl(TypeDeclDef),  // Type with explicit language mappings
    Function(FunctionDecl),
}

/// Type declaration with explicit language mappings
/// `type Tensor { rust: "gridmesh::tensor::Tensor<f32>", python: "gridmesh.Tensor" }`
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDeclDef {
    pub name: String,
    pub rust_impl: Option<String>,
    pub python_impl: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDecl {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub return_type: Option<Type>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<Variant>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    pub name: String,
    pub fields: Vec<Type>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Primitive(PrimitiveType),
    Named(String),
    Generic(String, Vec<Type>),
    Tuple(Vec<Type>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrimitiveType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    String,
    Bytes,
}

pub fn parse_interface(input: &str) -> Result<Vec<InterfaceItem>, String> {
    let (remaining, items) = many0(preceded(
        skip_ws_and_comments,
        alt((
            map(parse_function_decl, InterfaceItem::Function),
            map(parse_enum, InterfaceItem::Enum),
            map(parse_type_alias, |(n, t)| InterfaceItem::TypeAlias(n, t)),
            map(parse_type_decl, InterfaceItem::TypeDecl),
        )),
    ))
    .parse(input)
    .map_err(|e| format!("Parse error: {:?}", e))?;

    Ok(items)
}

/// Skip whitespace and // comments
fn skip_ws_and_comments(input: &str) -> IResult<&str, ()> {
    let mut remaining = input;
    loop {
        let (rest, _) = multispace0(remaining)?;
        remaining = rest;
        
        // Check for line comment
        if remaining.starts_with("//") {
            // Skip to end of line
            if let Some(newline_pos) = remaining.find('\n') {
                remaining = &remaining[newline_pos + 1..];
            } else {
                remaining = "";
            }
        } else {
            break;
        }
    }
    Ok((remaining, ()))
}

fn parse_function_decl(input: &str) -> IResult<&str, FunctionDecl> {
    let (input, _) = tag("fn")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, params) = delimited(
        char('('),
        separated_list0(
            preceded(multispace0, char(',')),
            preceded(multispace0, parse_param),
        ),
        preceded(multispace0, char(')')),
    ).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, return_type) = opt(preceded(
        pair(tag("->"), multispace0),
        parse_type,
    )).parse(input)?;
    
    Ok((input, FunctionDecl {
        name: name.to_string(),
        params,
        return_type,
    }))
}

fn parse_param(input: &str) -> IResult<&str, (String, Type)> {
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, ty) = parse_type(input)?;
    Ok((input, (name.to_string(), ty)))
}

fn parse_struct(input: &str) -> IResult<&str, StructDef> {
    let (input, _) = tag("struct")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, fields) = delimited(
        char('{'),
        many0(preceded(multispace0, parse_field)),
        preceded(multispace0, char('}')),
    )
    .parse(input)?;

    Ok((
        input,
        StructDef {
            name: name.to_string(),
            fields,
        },
    ))
}

fn parse_field(input: &str) -> IResult<&str, Field> {
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, ty) = parse_type(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = opt(char(',')).parse(input)?;

    Ok((
        input,
        Field {
            name: name.to_string(),
            ty,
        },
    ))
}

fn parse_enum(input: &str) -> IResult<&str, EnumDef> {
    let (input, _) = tag("enum")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, variants) = delimited(
        char('{'),
        separated_list0(
            preceded(multispace0, char(',')),
            preceded(multispace0, parse_variant),
        ),
        preceded(multispace0, char('}')),
    )
    .parse(input)?;

    Ok((
        input,
        EnumDef {
            name: name.to_string(),
            variants,
        },
    ))
}

fn parse_variant(input: &str) -> IResult<&str, Variant> {
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, fields) = opt(delimited(
        char('('),
        separated_list0(
            preceded(multispace0, char(',')),
            preceded(multispace0, parse_type),
        ),
        preceded(multispace0, char(')')),
    ))
    .parse(input)?;

    Ok((
        input,
        Variant {
            name: name.to_string(),
            fields: fields.unwrap_or_default(),
        },
    ))
}

fn parse_type_alias(input: &str) -> IResult<&str, (String, Type)> {
    let (input, _) = tag("type")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('=')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, ty) = parse_type(input)?;
    let (input, _) = multispace0(input)?;

    Ok((input, (name.to_string(), ty)))
}

/// Parse type declaration with optional explicit mappings
/// Supports: `type Tensor` or `type Tensor { rust: "...", python: "..." }`
fn parse_type_decl(input: &str) -> IResult<&str, TypeDeclDef> {
    let (input, _) = tag("type")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    
    // Make sure this is NOT followed by '=' (that would be a type alias)
    if input.starts_with('=') {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }
    
    // Check for optional body with explicit mappings
    if input.starts_with('{') {
        let (input, _) = char('{')(input)?;
        let (input, _) = multispace0(input)?;
        
        // Parse key-value pairs: rust: "...", python: "..."
        let mut rust_impl = None;
        let mut python_impl = None;
        let mut remaining = input;
        
        loop {
            let (input, _) = multispace0(remaining)?;
            if input.starts_with('}') {
                remaining = &input[1..];
                break;
            }
            
            // Parse key
            let (input, key) = parse_ident(input)?;
            let (input, _) = multispace0(input)?;
            let (input, _) = char(':')(input)?;
            let (input, _) = multispace0(input)?;
            
            // Parse quoted string value
            let (input, _) = char('"')(input)?;
            let end_quote = input.find('"').unwrap_or(input.len());
            let value = &input[..end_quote];
            let input = &input[end_quote + 1..];
            
            match key {
                "rust" => rust_impl = Some(value.to_string()),
                "python" => python_impl = Some(value.to_string()),
                _ => {} // Ignore unknown keys
            }
            
            // Skip comma if present
            let (input, _) = multispace0(input)?;
            let input = if input.starts_with(',') { &input[1..] } else { input };
            remaining = input;
        }
        
        Ok((remaining, TypeDeclDef {
            name: name.to_string(),
            rust_impl,
            python_impl,
        }))
    } else {
        // Simple opaque type without mappings
        Ok((input, TypeDeclDef {
            name: name.to_string(),
            rust_impl: None,
            python_impl: None,
        }))
    }
}

fn parse_type(input: &str) -> IResult<&str, Type> {
    alt((
        parse_primitive_type,
        parse_tuple_type,
        parse_generic_or_named,
    ))
    .parse(input)
}

fn parse_primitive_type(input: &str) -> IResult<&str, Type> {
    let (input, name) = alt((
        tag("bool"),
        tag("u8"),
        tag("u16"),
        tag("u32"),
        tag("u64"),
        tag("i8"),
        tag("i16"),
        tag("i32"),
        tag("i64"),
        tag("f32"),
        tag("f64"),
        tag("string"),
        tag("bytes"),
    ))
    .parse(input)?;

    let prim = match name {
        "bool" => PrimitiveType::Bool,
        "u8" => PrimitiveType::U8,
        "u16" => PrimitiveType::U16,
        "u32" => PrimitiveType::U32,
        "u64" => PrimitiveType::U64,
        "i8" => PrimitiveType::I8,
        "i16" => PrimitiveType::I16,
        "i32" => PrimitiveType::I32,
        "i64" => PrimitiveType::I64,
        "f32" => PrimitiveType::F32,
        "f64" => PrimitiveType::F64,
        "string" => PrimitiveType::String,
        "bytes" => PrimitiveType::Bytes,
        _ => unreachable!(),
    };

    Ok((input, Type::Primitive(prim)))
}

fn parse_generic_or_named(input: &str) -> IResult<&str, Type> {
    let (input, name) = parse_ident(input)?;
    let (input, _) = multispace0(input)?;
    let (input, params) = opt(delimited(
        char('<'),
        separated_list0(
            preceded(multispace0, char(',')),
            preceded(multispace0, parse_type),
        ),
        preceded(multispace0, char('>')),
    ))
    .parse(input)?;

    match params {
        Some(params) if !params.is_empty() => Ok((input, Type::Generic(name.to_string(), params))),
        _ => Ok((input, Type::Named(name.to_string()))),
    }
}

fn parse_tuple_type(input: &str) -> IResult<&str, Type> {
    let (input, types) = delimited(
        char('('),
        separated_list0(
            preceded(multispace0, char(',')),
            preceded(multispace0, parse_type),
        ),
        preceded(multispace0, char(')')),
    )
    .parse(input)?;

    Ok((input, Type::Tuple(types)))
}

fn parse_ident(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0(alt((alphanumeric1, tag("_")))),
    ))
    .parse(input)
}
