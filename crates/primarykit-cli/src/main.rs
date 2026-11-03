use std::env;
use std::path::PathBuf;
use std::process;

use primarykit::{create_project_with_template, ProjectTemplate};

const USAGE: &str =
    "Usage:\n  primarykit new <project_name> [--template basic|postgres] [--output <directory>]\n  primarykit --help";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("new") => {
            let name = args.next().ok_or_else(|| USAGE.to_owned())?;
            let mut output_root = PathBuf::from(".");
            let mut template = ProjectTemplate::Basic;

            while let Some(option) = args.next() {
                match option.as_str() {
                    "--output" => {
                        output_root = PathBuf::from(
                            args.next()
                                .ok_or_else(|| "--output requires a directory".to_owned())?,
                        );
                    }
                    "--template" => {
                        template = match args.next().as_deref() {
                            Some("basic") => ProjectTemplate::Basic,
                            Some("postgres") => ProjectTemplate::Postgres,
                            _ => return Err("--template requires basic or postgres".to_owned()),
                        };
                    }
                    _ => return Err(format!("unknown option: {option}\n{USAGE}")),
                }
            }

            let created = create_project_with_template(&name, &output_root, template)
                .map_err(|error| format!("failed to create project: {error}"))?;
            println!("Created project: {}", created.display());
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    }
}
