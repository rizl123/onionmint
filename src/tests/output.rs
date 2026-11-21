use crate::config::Config;
use crate::output::{base64, emit};
use crate::tests::support::temp_path;
use std::fs::{self, File};
use std::sync::Mutex;

#[test]
fn base64_encodes_partial_chunks_with_padding() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
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

#[test]
fn tor_key_files_match_rfc8032_ed25519_vector() {
    let output_dir = temp_path("rfc8032");
    let pk = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sk = hex::<64>(
        "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f",
    );
    let name = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
    let cfg = Config {
        output_dir: output_dir.clone(),
        names_only: true,
        ..Config::default()
    };

    emit(&cfg, name, &pk, &sk, &Mutex::new(None)).unwrap();
    let key_dir = output_dir.join(name);
    assert_eq!(
        fs::read(key_dir.join("hostname")).unwrap(),
        format!("{name}\n").as_bytes()
    );
    assert_eq!(
        fs::read(key_dir.join("hs_ed25519_public_key")).unwrap(),
        tor_key("public", &pk)
    );
    assert_eq!(
        fs::read(key_dir.join("hs_ed25519_secret_key")).unwrap(),
        tor_key("secret", &sk)
    );
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn emitting_existing_address_fails_without_overwriting_key_material() {
    let output_dir = temp_path("existing");
    let name = "alreadyhere.onion";
    let cfg = Config {
        output_dir: output_dir.clone(),
        names_only: true,
        ..Config::default()
    };
    emit(&cfg, name, &[1; 32], &[2; 64], &Mutex::new(None)).unwrap();
    let secret_path = output_dir.join(name).join("hs_ed25519_secret_key");
    let before = fs::read(&secret_path).unwrap();

    let error = emit(&cfg, name, &[3; 32], &[4; 64], &Mutex::new(None)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(secret_path).unwrap(), before);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn partial_key_write_failure_rolls_back_files_created_by_attempt() {
    let output_dir = temp_path("partial");
    let name = "partialwrite.onion";
    let key_dir = output_dir.join(name);
    fs::create_dir_all(key_dir.join("hostname")).unwrap();
    let cfg = Config {
        output_dir: output_dir.clone(),
        names_only: true,
        ..Config::default()
    };

    assert!(emit(&cfg, name, &[1; 32], &[2; 64], &Mutex::new(None)).is_err());
    assert!(!key_dir.join("hs_ed25519_secret_key").exists());
    assert!(!key_dir.join("hs_ed25519_public_key").exists());
    assert!(key_dir.join("hostname").is_dir());
    let _ = fs::remove_dir_all(output_dir);
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

fn tor_key(kind: &str, key: &[u8]) -> Vec<u8> {
    let mut result = format!("== ed25519v1-{kind}: type0 ==\0\0\0").into_bytes();
    result.extend_from_slice(key);
    result
}
