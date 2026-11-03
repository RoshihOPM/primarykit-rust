use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const TEMPLATES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../../../templates/basic/Cargo.toml")),
    ("src/main.rs", include_str!("../../../templates/basic/src/main.rs")),
    (".gitignore", include_str!("../../../templates/basic/.gitignore")),
    (".dockerignore", include_str!("../../../templates/basic/.dockerignore")),
    ("Dockerfile", include_str!("../../../templates/basic/Dockerfile")),
    ("README.md", include_str!("../../../templates/basic/README.md")),
];

/// Generate an independent project. Files are embedded into the CLI at build time.
pub fn create_project(name: &str, output_root: &Path) -> io::Result<PathBuf> {
    if !valid_project_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "project name must start with a lowercase ASCII letter and contain only lowercase ASCII letters, digits, or underscores (max 63 characters)",
        ));
    }

    fs::create_dir_all(output_root)?;
    let destination = output_root.join(name);
    // A pre-existing project must never be modified or overwritten.
    fs::create_dir(&destination)?;

    for (relative_path, source) in TEMPLATES {
        let target = destination.join(relative_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, source.replace("{{project_name}}", name))?;
    }

    Ok(destination)
}

fn valid_project_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "primarykit-test-{}-{timestamp}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create temporary directory");
            Self(root)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generates_a_standalone_axum_project() {
        let root = TestDirectory::new();
        let output = create_project("inventory_api", &root.0).expect("generate project");

        let manifest = fs::read_to_string(output.join("Cargo.toml")).expect("manifest");
        assert!(manifest.contains("name = \"inventory_api\""));
        assert!(manifest.contains("axum"));
        assert!(output.join("src/main.rs").is_file());
        assert!(output.join("Dockerfile").is_file());
        assert!(output.join("README.md").is_file());
    }

    #[test]
    fn rejects_invalid_names_without_creating_a_project() {
        let root = TestDirectory::new();
        for name in ["../escape", "bad-name", "Upper", "_prefix", ""] {
            let result = create_project(name, &root.0);
            assert_eq!(result.expect_err("must fail").kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn never_overwrites_existing_project() {
        let root = TestDirectory::new();
        create_project("orders", &root.0).expect("first create");
        let marker = root.0.join("orders").join("marker.txt");
        fs::write(&marker, "keep").expect("write marker");

        let error = create_project("orders", &root.0).expect_err("must not overwrite");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(marker).expect("marker"), "keep");
    }

    #[test]
    fn accepts_only_valid_package_names() {
        assert!(valid_project_name("a"));
        assert!(valid_project_name("my_service_2"));
        assert!(!valid_project_name("2service"));
        assert!(!valid_project_name("UPPER"));
        assert!(!valid_project_name(&"a".repeat(64)));
    }
}
