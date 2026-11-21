use crate::crypto::{
    KeyCursor, base32, matches_filter, matches_public_key, onion_name, parse_filters, prefix_match,
};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

#[test]
fn base32_matches_rfc4648_vectors_without_padding() {
    let cases = [
        (b"".as_slice(), ""),
        (b"f", "my"),
        (b"fo", "mzxq"),
        (b"foo", "mzxw6"),
        (b"foob", "mzxw6yq"),
        (b"fooba", "mzxw6ytb"),
        (b"foobar", "mzxw6ytboi"),
    ];

    for (input, expected) in cases {
        assert_eq!(base32(input), expected);
    }
}

#[test]
fn onion_name_has_v3_address_shape() {
    let address = onion_name(&[0; 32]);
    let host = address.strip_suffix(".onion").unwrap();

    assert_eq!(host.len(), 56);
    assert!(
        host.bytes()
            .all(|byte| b"abcdefghijklmnopqrstuvwxyz234567".contains(&byte))
    );
    assert_eq!(host.as_bytes()[55], b'd'); // Version byte 3 encodes as the final symbol.
    assert_eq!(
        host,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
    );
}

#[test]
fn incremental_cursor_public_points_match_the_exported_secret_scalars() {
    let step_point = EdwardsPoint::mul_base(&Scalar::from(8u64));
    let mut cursor = KeyCursor::random();

    for _ in 0..128 {
        let public_key = cursor.public_key();
        let secret_key = cursor.secret_key();
        let scalar_bytes: [u8; 32] = secret_key[..32].try_into().unwrap();
        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let expected = EdwardsPoint::mul_base(&scalar).compress().to_bytes();

        assert_eq!(public_key, expected);
        assert!(cursor.advance(&step_point));
    }
}

#[test]
fn optimized_filter_matching_agrees_with_base32_prefixes_at_boundaries() {
    let public_key = EdwardsPoint::mul_base(&Scalar::from(123_456_789u64))
        .compress()
        .to_bytes();
    let encoded = base32(&public_key);

    for length in [1, 2, 7, 51, 52] {
        let prefix = encoded[..length].to_owned();
        let filters = parse_filters(std::slice::from_ref(&prefix));
        assert!(
            matches_public_key(&public_key, &filters, 1),
            "length {length}"
        );

        let mut wrong = prefix.clone().into_bytes();
        let value = crate::crypto::ALPHABET
            .iter()
            .position(|&c| c == wrong[length - 1])
            .unwrap();
        let flip = if length == 52 { 0b1_0000 } else { 1 };
        wrong[length - 1] = crate::crypto::ALPHABET[value ^ flip];
        let wrong = String::from_utf8(wrong).unwrap();
        let wrong_filters = parse_filters(std::slice::from_ref(&wrong));
        assert!(
            !matches_public_key(&public_key, &wrong_filters, 1),
            "length {length}"
        );
    }
}

#[test]
fn optimized_filter_matching_supports_consecutive_prefixes() {
    let public_key = EdwardsPoint::mul_base(&Scalar::from(987_654_321u64))
        .compress()
        .to_bytes();
    let encoded = base32(&public_key);
    let filters = parse_filters(&[encoded[..2].to_owned(), encoded[2..5].to_owned()]);

    assert!(matches_public_key(&public_key, &filters, 2));
    assert!(!matches_public_key(&public_key, &filters, 100));
}

#[test]
fn prefix_match_checks_the_partial_final_base32_symbol() {
    let prefix = format!("{}q", "a".repeat(51));
    let matching = format!("{}r", "a".repeat(51));
    let nonmatching = format!("{}b", "a".repeat(51));

    assert!(prefix_match(&matching, &prefix));
    assert!(!prefix_match(&nonmatching, &prefix));
}

#[test]
fn prefix_match_handles_short_and_full_length_filters() {
    assert!(prefix_match("nekokitten", "neko"));
    assert!(!prefix_match("nekokitten", "neka"));

    let filter = "a".repeat(52);
    assert!(prefix_match(&filter, &filter));
    assert!(!prefix_match(&format!("{}q", "a".repeat(51)), &filter));
    assert!(!prefix_match(&"a".repeat(51), &filter));
}

#[test]
fn matches_filter_supports_consecutive_words() {
    let address = "nekocatxyz.onion";
    let filters = vec!["neko".to_owned(), "cat".to_owned()];

    assert!(matches_filter(address, &filters, 2));
    assert!(!matches_filter(address, &filters, 3));
    assert!(matches_filter(address, &filters, 1));
}

#[test]
fn matches_filter_accepts_any_matching_first_filter() {
    let filters = vec!["cat".to_owned(), "neko".to_owned()];

    assert!(matches_filter("nekoname.onion", &filters, 1));
    assert!(matches_filter("catname.onion", &filters, 1));
    assert!(!matches_filter("dogname.onion", &filters, 1));
}
