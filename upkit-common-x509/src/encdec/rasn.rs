use rasn_pkix::DisplayText;

pub fn display_text_as_string(display_text: &DisplayText) -> String {
    match display_text {
        DisplayText::Ia5String(s) => s.to_string(),
        DisplayText::VisibleString(s) => s.to_string(),
        DisplayText::BmpString(s) => s
            .iter()
            .map(|c| char::from_u32(*c as u32).unwrap())
            .collect::<String>(),
        DisplayText::Utf8String(s) => s.to_string(),
    }
}

pub fn integer_as_usize(value: &rasn::types::Integer) -> usize {
    match value {
        rasn::types::Integer::Primitive(value) => usize::try_from(*value).unwrap(),
        rasn::types::Integer::Variable(value) => {
            let (sign, dig) = value.to_u32_digits();
            if sign.eq(&num_bigint::Sign::Minus) || dig.len() != 1 {
                0
            } else {
                usize::try_from(*dig.first().unwrap()).unwrap()
            }
        }
    }
}

pub fn integer_as_isize(value: &rasn::types::Integer) -> isize {
    match value {
        rasn::types::Integer::Primitive(value) => *value,
        rasn::types::Integer::Variable(value) => {
            let (sign, dig) = value.to_u32_digits();
            if sign.eq(&num_bigint::Sign::Minus) || dig.len() != 1 {
                -isize::try_from(*dig.first().unwrap()).unwrap()
            } else {
                isize::try_from(*dig.first().unwrap()).unwrap()
            }
        }
    }
}

pub fn integer_as_bytes_be(value: &rasn::types::Integer) -> Vec<u8> {
    match value {
        rasn::types::Integer::Primitive(value) => (*value).to_be_bytes().to_vec(),
        rasn::types::Integer::Variable(value) => value.to_signed_bytes_be(),
    }
}
