//! Property-based tests for the core wire types.

use hsm_core::{KeyId, SignatureAlgorithm};
use proptest::collection::vec;
use proptest::prelude::*;

const ALLOWED: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:";

fn allowed_char() -> impl Strategy<Value = char> {
    (0..ALLOWED.len()).prop_map(move |i| ALLOWED[i] as char)
}

fn allowed_boundary_ids() -> impl Strategy<Value = String> {
    vec(allowed_char(), 100..140).prop_map(|cs| cs.into_iter().collect())
}

fn arbitrary_strings() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => any::<String>(),
        1 => vec(any::<char>(), 0..300).prop_map(|cs| cs.into_iter().collect()),
        1 => Just(String::new()),
    ]
}

fn spec_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

proptest! {
    #[test]
    fn key_id_acceptance_matches_spec_exactly(s in arbitrary_strings()) {
        match (KeyId::new(s.clone()), spec_valid(&s)) {
            (Ok(kid), true) => {
                prop_assert_eq!(kid.as_str(), s.as_str());
                prop_assert_eq!(kid.to_string(), s);
                prop_assert_eq!(KeyId::new(kid.to_string()).unwrap(), kid);
            }
            (Err(_), false) => {}
            (Ok(_), false) => panic!("accepted spec-invalid id: {s:?}"),
            (Err(_), true) => panic!("rejected spec-valid id: {s:?}"),
        }
    }

    #[test]
    fn key_id_length_boundary(s in allowed_boundary_ids()) {
        let expected = s.len() <= 128;
        prop_assert_eq!(KeyId::new(s.clone()).is_ok(), expected, "len={}", s.len());
    }

    #[test]
    fn key_id_deserialization_validates(s in arbitrary_strings()) {
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Result<KeyId, _> = serde_json::from_str(&json);
        prop_assert_eq!(parsed.is_ok(), spec_valid(&s));
    }

    #[test]
    fn signature_algorithm_wire_name_is_exact(s in arbitrary_strings()) {
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Result<SignatureAlgorithm, _> = serde_json::from_str(&json);
        if s == "ECDSA_P256_SHA256" {
            let alg = parsed.expect("canonical wire name must parse");
            prop_assert_eq!(serde_json::to_string(&alg).unwrap(), "\"ECDSA_P256_SHA256\"");
            prop_assert_eq!(alg.to_string(), "ECDSA_P256_SHA256");
        } else {
            prop_assert!(parsed.is_err(), "unexpectedly parsed: {s:?}");
        }
    }
}
