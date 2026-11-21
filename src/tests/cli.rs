use crate::cli::parse_args_from;
use crate::tests::support::temp_path;
use std::fs;
use std::path::PathBuf;

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
    assert_eq!(raw_yaml.err().unwrap(), "--rawyaml requires -y or -Y");

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
