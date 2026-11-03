use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path};

const GENERATOR: &str = "primarykit-rust";
const MODULE_START: &str = "// primarykit:modules:start\n";
const MODULE_END: &str = "// primarykit:modules:end\n";
const DEPENDENCIES_START: &str = "# primarykit:dependencies:start\n";
const DEPENDENCIES_END: &str = "# primarykit:dependencies:end\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectOrigin {
    pub generator: String,
    pub schema_version: u32,
    pub template: String,
    pub modules: Vec<String>,
}

impl ProjectOrigin {
    pub fn new(template: &str) -> Self {
        Self {
            generator: GENERATOR.to_owned(),
            schema_version: 1,
            template: template.to_owned(),
            modules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub dependencies: &'static [&'static str],
    pub requires_postgres: bool,
    cargo_dependencies: &'static [&'static str],
    files: &'static [ModuleFile],
}

#[derive(Debug, Clone, Copy)]
struct ModuleFile {
    path: &'static str,
    source: &'static str,
}

static API_ERRORS_FILES: &[ModuleFile] = &[ModuleFile {
    path: "src/modules/api_errors.rs",
    source: include_str!("../../../modules/api_errors/api_errors.rs"),
}];
static PAGINATION_FILES: &[ModuleFile] = &[ModuleFile {
    path: "src/modules/pagination.rs",
    source: include_str!("../../../modules/pagination/pagination.rs"),
}];
static AUDIT_FILES: &[ModuleFile] = &[
    ModuleFile {
        path: "src/modules/audit.rs",
        source: include_str!("../../../modules/audit/audit.rs"),
    },
    ModuleFile {
        path: "migrations/20261103000001_create_audit_events.sql",
        source: include_str!("../../../modules/audit/20261103000001_create_audit_events.sql"),
    },
];

static AUTH_FILES: &[ModuleFile] = &[
    ModuleFile {
        path: "src/modules/auth.rs",
        source: include_str!("../../../modules/auth/auth.rs"),
    },
    ModuleFile {
        path: "migrations/20261103000002_create_auth.sql",
        source: include_str!("../../../modules/auth/20261103000002_create_auth.sql"),
    },
];
static PERMISSIONS_FILES: &[ModuleFile] = &[
    ModuleFile {
        path: "src/modules/permissions.rs",
        source: include_str!("../../../modules/permissions/permissions.rs"),
    },
    ModuleFile {
        path: "migrations/20261103000003_create_rbac.sql",
        source: include_str!("../../../modules/permissions/20261103000003_create_rbac.sql"),
    },
];

pub static MODULES: &[ModuleInfo] = &[
    ModuleInfo {
        name: "api_errors",
        description: "Structured JSON API errors",
        dependencies: &[],
        requires_postgres: false,
        cargo_dependencies: &[],
        files: API_ERRORS_FILES,
    },
    ModuleInfo {
        name: "pagination",
        description: "Validated pagination parameters",
        dependencies: &["api_errors"],
        requires_postgres: false,
        cargo_dependencies: &[],
        files: PAGINATION_FILES,
    },
    ModuleInfo {
        name: "audit",
        description: "Transactional PostgreSQL audit events",
        dependencies: &[],
        requires_postgres: true,
        cargo_dependencies: &[],
        files: AUDIT_FILES,
    },
    ModuleInfo {
        name: "auth",
        description: "Argon2id password hashes and revocable opaque PostgreSQL sessions",
        dependencies: &[],
        requires_postgres: true,
        cargo_dependencies: &[
            "argon2 = \"0.5\"",
            "hex = \"0.4\"",
            "rand = \"0.8\"",
            "sha2 = \"0.10\"",
            "thiserror = \"2\"",
        ],
        files: AUTH_FILES,
    },
    ModuleInfo {
        name: "permissions",
        description: "Fail-closed tenant-scoped role-based permissions",
        dependencies: &["auth"],
        requires_postgres: true,
        cargo_dependencies: &[],
        files: PERMISSIONS_FILES,
    },
];

pub fn available_modules() -> &'static [ModuleInfo] {
    MODULES
}

pub fn initial_modules_source() -> String {
    managed_block(&[])
}

fn managed_dependencies(modules: &[String]) -> String {
    let mut requirements = BTreeSet::new();
    for name in modules {
        if let Some(module) = find_module(name) {
            requirements.extend(module.cargo_dependencies.iter().copied());
        }
    }
    let mut source = DEPENDENCIES_START.to_owned();
    for requirement in requirements {
        source.push_str(requirement);
        source.push('\n');
    }
    source.push_str(DEPENDENCIES_END);
    source
}

pub fn origin_json(template: &str) -> io::Result<String> {
    let origin = ProjectOrigin::new(template);
    encode_origin(&origin)
}

fn encode_origin(origin: &ProjectOrigin) -> io::Result<String> {
    let mut encoded = serde_json::to_string_pretty(origin).map_err(io::Error::other)?;
    encoded.push('\n');
    Ok(encoded)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_origin(origin: &ProjectOrigin) -> io::Result<()> {
    if origin.generator != GENERATOR || origin.schema_version != 1 {
        return Err(invalid("unsupported project provenance"));
    }
    if origin.template != "basic" && origin.template != "postgres" {
        return Err(invalid("unrecognized project template"));
    }
    let mut seen = BTreeSet::new();
    for name in &origin.modules {
        if !seen.insert(name.as_str()) {
            return Err(invalid("duplicate installed module"));
        }
        let module = find_module(name).ok_or_else(|| invalid("unknown installed module"))?;
        if module.requires_postgres && origin.template != "postgres" {
            return Err(invalid("PostgreSQL module installed into basic template"));
        }
        if !module.dependencies.iter().all(|dependency| {
            origin
                .modules
                .iter()
                .any(|installed| installed == dependency)
        }) {
            return Err(invalid("installed module is missing a dependency"));
        }
    }
    Ok(())
}

fn find_module(name: &str) -> Option<&'static ModuleInfo> {
    MODULES.iter().find(|module| module.name == name)
}

fn collect_dependencies(
    name: &str,
    template: &str,
    visiting: &mut BTreeSet<&'static str>,
    visited: &mut BTreeSet<&'static str>,
    result: &mut Vec<&'static ModuleInfo>,
) -> io::Result<()> {
    let module = find_module(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown module: {name}"),
        )
    })?;
    if module.requires_postgres && template != "postgres" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("module {} requires the postgres template", module.name),
        ));
    }
    if visited.contains(module.name) {
        return Ok(());
    }
    if !visiting.insert(module.name) {
        return Err(invalid("module dependency cycle"));
    }
    for dependency in module.dependencies {
        collect_dependencies(dependency, template, visiting, visited, result)?;
    }
    visiting.remove(module.name);
    visited.insert(module.name);
    result.push(module);
    Ok(())
}

fn managed_block(modules: &[String]) -> String {
    let mut block = MODULE_START.to_owned();
    let mut names = modules.to_vec();
    names.sort();
    for module in &names {
        block.push_str(&format!("pub mod {module};\n"));
    }
    block.push_str(MODULE_END);
    block
}

fn assert_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(format!(
            "expected regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn assert_safe_parent(project: &Path, path: &Path) -> io::Result<()> {
    let relative = path
        .strip_prefix(project)
        .map_err(|_| invalid("destination outside project"))?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(invalid("unsafe module destination"));
        }
    }
    let mut current = project.to_path_buf();
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(invalid(format!("unsafe directory: {}", current.display())));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// Install a module and its dependencies without overwriting application code.
/// The generator only updates the clearly marked module-registration block.
pub fn install_module(project: &Path, module_name: &str) -> io::Result<Vec<String>> {
    let project = project.canonicalize()?;
    let origin_path = project.join("primarykit-origin.json");
    let registration_path = project.join("src/modules/mod.rs");
    // Validate parent directories before reading or writing managed project files.
    // A symlinked src/modules directory could otherwise redirect writes
    // outside of the project even if mod.rs itself is a regular file.
    assert_safe_parent(&project, &registration_path)?;
    assert_safe_parent(&project, &project.join("src/lib.rs"))?;
    assert_regular_file(&origin_path)?;
    assert_regular_file(&registration_path)?;
    assert_regular_file(&project.join("Cargo.toml"))?;
    assert_regular_file(&project.join("src/lib.rs"))?;

    let manifest_path = project.join("Cargo.toml");
    let original_manifest = fs::read_to_string(&manifest_path)?;
    let original_origin = fs::read_to_string(&origin_path)?;
    let mut origin: ProjectOrigin =
        serde_json::from_str(&original_origin).map_err(|error| invalid(error.to_string()))?;
    validate_origin(&origin)?;
    let original_registration = fs::read_to_string(&registration_path)?;
    let old_block = managed_block(&origin.modules);
    if original_registration.matches(&old_block).count() != 1 {
        return Err(invalid(
            "module registration was edited; refusing to overwrite",
        ));
    }

    let mut resolved = Vec::new();
    collect_dependencies(
        module_name,
        &origin.template,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut resolved,
    )?;

    if origin.modules.iter().any(|name| name == module_name) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("module already installed: {module_name}"),
        ));
    }

    let pending: Vec<_> = resolved
        .into_iter()
        .filter(|module| !origin.modules.iter().any(|name| name == module.name))
        .collect();

    let mut files = Vec::new();
    for module in &pending {
        for file in module.files {
            let target = project.join(file.path);
            assert_safe_parent(&project, &target)?;
            if fs::symlink_metadata(&target).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to overwrite {}", target.display()),
                ));
            }
            files.push((target, file.source));
        }
    }

    let old_dependencies_block = managed_dependencies(&origin.modules);
    let installed: Vec<String> = pending
        .iter()
        .map(|module| module.name.to_owned())
        .collect();
    origin.modules.extend(installed.iter().cloned());
    origin.modules.sort();
    let new_dependencies_block = managed_dependencies(&origin.modules);
    let next_manifest = if old_dependencies_block == new_dependencies_block {
        None
    } else {
        if original_manifest.matches(&old_dependencies_block).count() != 1 {
            return Err(invalid(
                "missing or modified managed Cargo dependencies block; refusing to edit manifest",
            ));
        }
        Some(original_manifest.replacen(&old_dependencies_block, &new_dependencies_block, 1))
    };
    let new_registration =
        original_registration.replacen(&old_block, &managed_block(&origin.modules), 1);
    let new_origin = encode_origin(&origin)?;

    let mut created = Vec::new();
    let result = (|| -> io::Result<()> {
        for (path, source) in files {
            fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| invalid("missing destination parent"))?,
            )?;
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            created.push(path);
            handle.write_all(source.as_bytes())?;
        }
        fs::write(&registration_path, &new_registration)?;
        if let Some(manifest) = &next_manifest {
            fs::write(&manifest_path, manifest)?;
        }
        fs::write(&origin_path, &new_origin)?;
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::write(&registration_path, original_registration);
        if next_manifest.is_some() {
            let _ = fs::write(&manifest_path, original_manifest);
        }
        let _ = fs::write(&origin_path, original_origin);
        for path in created.iter().rev() {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }

    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempProject(std::path::PathBuf);

    impl TempProject {
        fn new(template: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("primarykit-modules-{}-{nanos}", std::process::id()));
            fs::create_dir_all(path.join("src/modules")).expect("create test project");
            fs::write(
                path.join("Cargo.toml"),
                format!("[package]\nname=\"test\"\n[dependencies]\n{}", managed_dependencies(&[])),
            )
            .expect("manifest");
            fs::write(path.join("src/lib.rs"), "pub mod modules;\n").expect("library");
            fs::write(path.join("src/modules/mod.rs"), initial_modules_source())
                .expect("registration");
            fs::write(
                path.join("primarykit-origin.json"),
                origin_json(template).expect("provenance"),
            )
            .expect("provenance");
            Self(path)
        }
    }

    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn installs_dependencies_in_order_and_registers_modules() {
        let project = TempProject::new("basic");
        let added = install_module(&project.0, "pagination").expect("install");
        assert_eq!(added, ["api_errors", "pagination"]);
        let registry = fs::read_to_string(project.0.join("src/modules/mod.rs")).expect("registry");
        assert!(registry.contains("pub mod api_errors;"));
        assert!(registry.contains("pub mod pagination;"));
        assert!(project.0.join("src/modules/api_errors.rs").is_file());
        assert!(project.0.join("src/modules/pagination.rs").is_file());
        let origin: ProjectOrigin = serde_json::from_str(
            &fs::read_to_string(project.0.join("primarykit-origin.json")).expect("origin"),
        )
        .expect("valid origin");
        assert_eq!(origin.modules, ["api_errors", "pagination"]);
    }

    #[test]
    fn refuses_existing_module_and_preserves_content() {
        let project = TempProject::new("basic");
        install_module(&project.0, "api_errors").expect("initial install");
        let file = project.0.join("src/modules/api_errors.rs");
        fs::write(&file, "custom changes").expect("edit");
        let failure = install_module(&project.0, "api_errors").expect_err("must reject");
        assert_eq!(failure.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(file).expect("read"), "custom changes");
    }

    #[test]
    fn refuses_conflicting_files_without_partial_install() {
        let project = TempProject::new("basic");
        fs::write(project.0.join("src/modules/pagination.rs"), "user code").expect("write");
        let error = install_module(&project.0, "pagination").expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!project.0.join("src/modules/api_errors.rs").exists());
        assert_eq!(
            fs::read_to_string(project.0.join("src/modules/pagination.rs")).expect("read"),
            "user code"
        );
    }

    #[test]
    fn refuses_postgres_only_module_on_basic_template() {
        let project = TempProject::new("basic");
        let error = install_module(&project.0, "audit").expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn audit_installs_on_postgres_template() {
        let project = TempProject::new("postgres");
        assert_eq!(
            install_module(&project.0, "audit").expect("install"),
            ["audit"]
        );
        assert!(project.0.join("src/modules/audit.rs").is_file());
        assert!(project
            .0
            .join("migrations/20261103000001_create_audit_events.sql")
            .is_file());
    }

    #[test]
    fn installs_auth_and_permissions_with_only_needed_dependencies() {
        let project = TempProject::new("postgres");
        let added = install_module(&project.0, "permissions").expect("install permissions");
        assert_eq!(added, ["auth", "permissions"]);
        assert!(project.0.join("src/modules/auth.rs").is_file());
        assert!(project.0.join("src/modules/permissions.rs").is_file());
        assert!(project
            .0
            .join("migrations/20261103000002_create_auth.sql")
            .is_file());
        let manifest = fs::read_to_string(project.0.join("Cargo.toml")).expect("manifest");
        assert!(manifest.contains("argon2 = \"0.5\""));
        assert!(manifest.contains("thiserror = \"2\""));
        assert_eq!(manifest.matches("argon2 =").count(), 1);
    }

    #[test]
    fn rejects_auth_if_manifest_block_was_removed_without_partial_install() {
        let project = TempProject::new("postgres");
        let manifest = project.0.join("Cargo.toml");
        fs::write(&manifest, "[package]\nname=\"user_owned\"\n").expect("custom manifest");
        assert!(install_module(&project.0, "auth").is_err());
        assert_eq!(
            fs::read_to_string(manifest).expect("manifest"),
            "[package]\nname=\"user_owned\"\n"
        );
        assert!(!project.0.join("src/modules/auth.rs").exists());
    }

    #[test]
    fn rejects_auth_on_basic_template() {
        let project = TempProject::new("basic");
        let failure = install_module(&project.0, "auth").expect_err("postgres required");
        assert_eq!(failure.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn refuses_tampered_managed_registry() {
        let project = TempProject::new("basic");
        fs::write(
            project.0.join("src/modules/mod.rs"),
            "// user deleted markers\n",
        )
        .expect("tamper");
        assert!(install_module(&project.0, "api_errors").is_err());
        assert!(!project.0.join("src/modules/api_errors.rs").exists());
    }

    #[test]
    fn preserves_user_code_outside_managed_block() {
        let project = TempProject::new("basic");
        let registry = project.0.join("src/modules/mod.rs");
        fs::write(
            &registry,
            format!("// custom header\n{}", initial_modules_source()),
        )
        .expect("write custom content");
        install_module(&project.0, "api_errors").expect("install");
        assert!(fs::read_to_string(registry)
            .expect("read")
            .starts_with("// custom header\n"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_module_directory_even_with_valid_external_registry() {
        use std::os::unix::fs::symlink;
        let project = TempProject::new("basic");
        let external = TempProject::new("basic");
        let external_registry = external.0.join("src/modules/mod.rs");
        let original = fs::read_to_string(&external_registry).expect("external registry");

        fs::remove_file(project.0.join("src/modules/mod.rs")).expect("remove registry");
        fs::remove_dir(project.0.join("src/modules")).expect("remove directory");
        symlink(
            external.0.join("src/modules"),
            project.0.join("src/modules"),
        )
        .expect("symlink");

        assert!(install_module(&project.0, "api_errors").is_err());
        assert!(!external.0.join("src/modules/api_errors.rs").exists());
        assert_eq!(
            fs::read_to_string(external_registry).expect("external registry"),
            original
        );
    }
}
