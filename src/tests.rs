use crate::cli::parse_args_from;
use crate::config::Config;
use crate::crypto::{
    KeyCursor, base32, matches_filter, matches_public_key, onion_name, parse_filters, prefix_match,
};
use crate::output::{base64, emit};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::Mutex;

fn temp_path(label: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "onionmint-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

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
fn base64_encodes_partial_chunks_with_padding() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
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

#[test]
fn cli_parses_flags_and_filters() {
    let cfg = parse_args_from(
        vec!["-q", "-t", "2", "-n", "4", "-N", "2", "neko", "cat"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "onionmint",
        None,
    )
    .unwrap();

    assert_eq!(cfg.filters, ["neko", "cat"]);
    assert_eq!(cfg.threads, 2);
    assert_eq!(cfg.limit, 4);
    assert_eq!(cfg.words, 2);
    assert!(cfg.quiet);
}

#[test]
fn cli_filters_replace_config_filters_and_override_options() {
    let path = temp_path("config");
    fs::write(&path, "filters = [\"fromfile\"]\nthreads = 1\nkeys = 8\n").unwrap();
    let args = vec!["-c", path.to_str().unwrap(), "-t", "3", "cli"]
        .into_iter()
        .map(str::to_owned)
        .collect();

    let cfg = parse_args_from(args, "onionmint", None).unwrap();
    let _ = fs::remove_file(path);

    assert_eq!(cfg.filters, ["cli"]);
    assert_eq!(cfg.threads, 3);
    assert_eq!(cfg.limit, 8);
}

#[test]
fn filter_file_skips_comments_and_combines_cli_filters() {
    let path = temp_path("filters");
    fs::write(&path, "# comment\n\n// comment\nDOG\r\n").unwrap();
    let args = vec!["-f", path.to_str().unwrap(), "^NEKO"]
        .into_iter()
        .map(str::to_owned)
        .collect();

    let cfg = parse_args_from(args, "onionmint", None).unwrap();
    let _ = fs::remove_file(path);

    assert_eq!(cfg.filters, ["neko", "dog"]);
}

#[test]
fn cli_validates_yaml_and_positive_counts() {
    let raw_yaml = parse_args_from(
        vec!["--rawyaml", "neko"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "onionmint",
        None,
    );
    assert_eq!(raw_yaml.err().unwrap(), "--rawyaml requires -y");

    let zero_threads = parse_args_from(
        vec!["-t", "0", "neko"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "onionmint",
        None,
    );
    assert_eq!(
        zero_threads.err().unwrap(),
        "thread count and word count must be positive"
    );
}

#[test]
fn dedup_normalizes_case_and_leading_caret() {
    let args = vec!["-D", "NEKO", "neko", "^NeKo"]
        .into_iter()
        .map(str::to_owned)
        .collect();

    let cfg = parse_args_from(args, "onionmint", None).unwrap();

    assert_eq!(cfg.filters, ["neko"]);
}

#[test]
fn output_options_keep_append_and_overwrite_modes() {
    let append = parse_args_from(
        vec!["-o", "names.txt", "neko"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "onionmint",
        None,
    )
    .unwrap();
    let overwrite = parse_args_from(
        vec!["-O", "names.txt", "neko"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "onionmint",
        None,
    )
    .unwrap();

    assert_eq!(
        append.output_file,
        Some((PathBuf::from("names.txt"), false))
    );
    assert_eq!(
        overwrite.output_file,
        Some((PathBuf::from("names.txt"), true))
    );
}

#[test]
fn yaml_output_encodes_key_prefixes_or_raw_key_bytes() {
    let pk = [1; 32];
    let sk = [2; 64];
    for raw_yaml in [false, true] {
        let path = temp_path("yaml");
        let cfg = Config {
            yaml: true,
            raw_yaml,
            ..Config::default()
        };
        let output = Mutex::new(Some(File::create(&path).unwrap()));
        emit(&cfg, "nekoname.onion", &pk, &sk, &output).unwrap();
        drop(output);

        let record = fs::read_to_string(&path).unwrap();
        let (expected_pk, expected_sk) = if raw_yaml {
            (pk.to_vec(), sk.to_vec())
        } else {
            let mut public = b"== ed25519v1-public: type0 ==\0\0\0".to_vec();
            public.extend_from_slice(&pk);
            let mut secret = b"== ed25519v1-secret: type0 ==\0\0\0".to_vec();
            secret.extend_from_slice(&sk);
            (public, secret)
        };
        assert!(record.contains(&format!("hostname: nekoname.onion\n")));
        assert!(record.contains(&format!("hs_ed25519_public_key: {}", base64(&expected_pk))));
        assert!(record.contains(&format!("hs_ed25519_secret_key: {}", base64(&expected_sk))));
        let _ = fs::remove_file(path);
    }
}

#[test]
fn emit_writes_key_files_and_machine_readable_hostname() {
    let output_dir = temp_path("output");
    let name = "nekoname.onion";
    let cfg = Config {
        output_dir: output_dir.clone(),
        names_only: true,
        ..Config::default()
    };
    emit(&cfg, name, &[1; 32], &[2; 64], &Mutex::new(None)).unwrap();

    let key_dir = output_dir.join(name);
    assert_eq!(
        fs::read(key_dir.join("hostname")).unwrap(),
        b"nekoname.onion\n"
    );
    assert_eq!(
        fs::read(key_dir.join("hs_ed25519_public_key"))
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        fs::read(key_dir.join("hs_ed25519_secret_key"))
            .unwrap()
            .len(),
        96
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(key_dir.join("hs_ed25519_secret_key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let _ = fs::remove_dir_all(output_dir);
}
