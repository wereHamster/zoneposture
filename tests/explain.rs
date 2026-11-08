use std::process::{Command, Output};

fn zoneposture(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zoneposture"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn explain_prints_the_document_of_a_rule() {
    let output = zoneposture(&["explain", "caa-missing"]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("# caa-missing\n"), "{stdout}");
    assert!(stdout.contains("## Fix"), "{stdout}");
}

#[test]
fn explain_rejects_an_unknown_id_and_lists_the_known_ones() {
    let output = zoneposture(&["explain", "no-such-rule"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unknown finding id \"no-such-rule\""),
        "{stderr}"
    );
    assert!(stderr.contains("  caa-missing\n"), "{stderr}");
    assert!(stderr.contains("  security-txt-canonical\n"), "{stderr}");
}
