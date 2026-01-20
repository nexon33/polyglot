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
        multispace0,
        alt((
            map(parse_enum, InterfaceItem::Enum),
            map(parse_type_alias, |(n, t)| InterfaceItem::TypeAlias(n, t)),
        )),
    ))
    .parse(input)
    .map_err(|e| format!("Parse error: {:?}", e))?;

    Ok(items)
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
