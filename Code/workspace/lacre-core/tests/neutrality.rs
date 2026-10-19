//! E4 — A1/A7, mechanically: the Core neither depends on the layers that may
//! inspect content nor contains code that interprets it (Prime 4.2, 4.8, 7.3.1).
//!
//! The Core's `Cargo.toml` and sources are read as text. This is a structural
//! guarantee (no dependency path, no parsing library, no UTF-8/JSON/regex use);
//! the behavioural guarantee — seals and verdicts independent of content — is
//! in `properties.rs`.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// The text of `[dependencies]` only (not dev-dependencies).
fn normal_dependencies() -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in MANIFEST.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == "[dependencies]";
            continue;
        }
        if inside && !t.starts_with('#') {
            out.push_str(t);
            out.push('\n');
        }
    }
    out
}

fn core_sources() -> Vec<(String, String)> {
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "rs").then(|| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(&p).unwrap()))
        })
        .collect()
}

/// Production code of a file: everything before its `#[cfg(test)]` module, comments dropped.
fn production_code(text: &str) -> String {
    // Cut at the test MODULE, not at the first `#[cfg(test)]`: a bare `#[cfg(test)] use`
    // earlier in a file must not hide production code from the scan.
    let cut = text.find("#[cfg(test)]\nmod ").unwrap_or(text.len());
    text[..cut].lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

#[test]
fn the_core_does_not_depend_on_content_aware_or_runtime_layers() {
    let deps = normal_dependencies();
    for forbidden in [
        "lacre-profiles", "lacre-domain", "lacre-adapter", "lacre-server", "lacre-tokio",
        "tokio", "axum", "hyper", "regex", "serde", "serde_json", "async",
    ] {
        assert!(!deps.contains(forbidden), "lacre-core [dependencies] mentions `{forbidden}`:\n{deps}");
    }
}

#[test]
fn the_core_sources_do_not_reference_content_aware_layers_or_parsers() {
    for (file, text) in core_sources() {
        let code = production_code(&text);
        for forbidden in ["lacre_profiles", "lacre_domain", "serde_json", "regex::", "tokio::", "axum::", "async fn", ".await"] {
            assert!(!code.contains(forbidden), "{file}: production code mentions `{forbidden}`");
        }
    }
}

#[test]
fn the_core_never_interprets_payload_bytes_as_text() {
    for (file, text) in core_sources() {
        let code = production_code(&text);
        for forbidden in ["from_utf8", "String::from_utf8_lossy", "to_ascii_", ".chars()", "char::from"] {
            assert!(!code.contains(forbidden), "{file}: production code interprets bytes as text (`{forbidden}`)");
        }
    }
}
