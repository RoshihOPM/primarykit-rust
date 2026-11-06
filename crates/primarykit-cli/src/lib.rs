mod module_catalog;

pub use module_catalog::{available_modules, install_module, ModuleInfo};

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const TEMPLATES: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        include_str!("../../../templates/basic/Cargo.toml"),
    ),
    (
        "src/main.rs",
        include_str!("../../../templates/basic/src/main.rs"),
    ),
    (
        ".gitignore",
        include_str!("../../../templates/basic/.gitignore"),
    ),
    (
        ".dockerignore",
        include_str!("../../../templates/basic/.dockerignore"),
    ),
    (
        "Dockerfile",
        include_str!("../../../templates/basic/Dockerfile"),
    ),
    (
        "README.md",
        include_str!("../../../templates/basic/README.md"),
    ),
    (
        "AGENTS.md",
        include_str!("../../../templates/shared/AGENTS.md"),
    ),
];

const POSTGRES_TEMPLATES: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        include_str!("../../../templates/postgres/Cargo.toml"),
    ),
    (
        "src/main.rs",
        include_str!("../../../templates/postgres/src/main.rs"),
    ),
    (
        "migrations/20261103000000_create_examples.sql",
        include_str!("../../../templates/postgres/migrations/20261103000000_create_examples.sql"),
    ),
    (
        ".env.example",
        include_str!("../../../templates/postgres/.env.example"),
    ),
    (
        ".gitignore",
        include_str!("../../../templates/basic/.gitignore"),
    ),
    (
        ".dockerignore",
        include_str!("../../../templates/basic/.dockerignore"),
    ),
    (
        "Dockerfile",
        include_str!("../../../templates/postgres/Dockerfile"),
    ),
    (
        "compose.yaml",
        include_str!("../../../templates/postgres/compose.yaml"),
    ),
    (
        "README.md",
        include_str!("../../../templates/postgres/README.md"),
    ),
    (
        "AGENTS.md",
        include_str!("../../../templates/shared/AGENTS.md"),
    ),
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProjectTemplate {
    Basic,
    Postgres,
}

/// Generate an independent basic project.
pub fn create_project(name: &str, output_root: &Path) -> io::Result<PathBuf> {
    create_project_with_template(name, output_root, ProjectTemplate::Basic)
}

/// Generate an independent project. Files are embedded into the CLI at build time.
pub fn create_project_with_template(
    name: &str,
    output_root: &Path,
    template: ProjectTemplate,
) -> io::Result<PathBuf> {
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

    let files = match template {
        ProjectTemplate::Basic => TEMPLATES,
        ProjectTemplate::Postgres => POSTGRES_TEMPLATES,
    };
    for (relative_path, source) in files {
        let target = destination.join(relative_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, source.replace("{{project_name}}", name))?;
    }

    fs::write(destination.join("src/lib.rs"), "pub mod modules;\n")?;
    fs::create_dir_all(destination.join("src/modules"))?;
    fs::write(
        destination.join("src/modules/mod.rs"),
        module_catalog::initial_modules_source(),
    )?;
    let template_name = match template {
        ProjectTemplate::Basic => "basic",
        ProjectTemplate::Postgres => "postgres",
    };
    fs::write(
        destination.join("primarykit-origin.json"),
        module_catalog::origin_json(template_name)?,
    )?;

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
        assert!(manifest.contains("[workspace]"));
        assert!(output.join("src/main.rs").is_file());
        let dockerfile = fs::read_to_string(output.join("Dockerfile")).expect("dockerfile");
        assert_eq!(dockerfile.matches("@sha256:").count(), 2);
        assert!(dockerfile.contains("cargo build --locked --release"));
        assert!(output.join("README.md").is_file());
        assert!(output.join("AGENTS.md").is_file());
        assert!(output.join("src/lib.rs").is_file());
        assert!(output.join("src/modules/mod.rs").is_file());
        assert!(output.join("primarykit-origin.json").is_file());
    }

    #[test]
    fn rejects_invalid_names_without_creating_a_project() {
        let root = TestDirectory::new();
        for name in ["../escape", "bad-name", "Upper", "_prefix", ""] {
            let result = create_project(name, &root.0);
            assert_eq!(
                result.expect_err("must fail").kind(),
                io::ErrorKind::InvalidInput
            );
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
    fn generates_a_standalone_postgres_project() {
        let root = TestDirectory::new();
        let output =
            create_project_with_template("billing_api", &root.0, ProjectTemplate::Postgres)
                .expect("generate postgres project");
        let manifest = fs::read_to_string(output.join("Cargo.toml")).expect("manifest");
        assert!(manifest.contains("name = \"billing_api\""));
        assert!(manifest.contains("sqlx"));
        assert!(manifest.contains("[workspace]"));
        assert!(output
            .join("migrations/20261103000000_create_examples.sql")
            .is_file());
        assert!(output.join("compose.yaml").is_file());
        let dockerfile = fs::read_to_string(output.join("Dockerfile")).expect("dockerfile");
        assert_eq!(dockerfile.matches("@sha256:").count(), 2);
        assert!(dockerfile.contains("cargo build --locked --release"));
        assert!(output.join("AGENTS.md").is_file());
        assert!(output.join("primarykit-origin.json").is_file());
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
