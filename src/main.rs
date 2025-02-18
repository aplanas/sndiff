use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::str;

use clap::{Parser, Subcommand};
use colored::Colorize;
use semver::Version;
use serde::Serialize;
// use similar::DiffableStr;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Snapshot to compare with
    old_snapshot: Option<u32>,

    /// Optional reference snapshot.  If missing use the current one
    new_snapshot: Option<u32>,

    /// Report only changes in packages
    #[arg(long, short)]
    packages: bool,

    /// Report only changes in /etc
    #[arg(long, short)]
    etc: bool,

    /// Include diff output for changes
    #[arg(long, short)]
    full_diff: bool,

    /// JSON output
    #[arg(long, short)]
    json: bool,

    /// Disable colored output
    #[arg(long, short)]
    no_colors: bool,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List snapshots in the system
    List,
}

fn check_directory_exists_and_readable(dir_path: &str) -> Result<(), String> {
    let path = Path::new(dir_path);

    if !path.exists() {
        return Err(format!("Directory '{}' does not exist.", dir_path));
    }

    if !path.is_dir() {
        return Err(format!("'{}' is not a directory.", dir_path));
    }

    match fs::read_dir(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Err(format!(
                    "No read permission for directory '{}': {}",
                    dir_path, e
                ))
            } else {
                Err(format!("Error reading directory '{}': {}", dir_path, e))
            }
        }
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Package {
    name: String,
    version: String,
    changelog: Option<String>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PackageChange {
    name: String,
    version_from: String,
    version_to: String,
    changelog_diff: Option<String>,
}

#[derive(Debug, Serialize)]
struct PackageChanges {
    updated: Vec<PackageChange>,
    downgraded: Vec<PackageChange>,
    added: Vec<Package>,
    removed: Vec<Package>,
}

fn get_packages_from(snapshot: Option<u32>) -> Result<Vec<Package>, String> {
    let dbpath = if let Some(id) = snapshot {
        format!("/.snapshots/{id}/snapshot/usr/lib/sysimage/rpm")
    } else {
        "/usr/lib/sysimage/rpm".to_string()
    };

    let output = Command::new("rpm")
        .arg("-qa")
        .arg("--queryformat")
        .arg("%{NAME} %{VERSION}-%{RELEASE}\n")
        .arg("--dbpath")
        .arg(dbpath)
        .output()
        .map_err(|e| format!("Failed to execute rpm: {}", e))?;

    if !output.status.success() {
        println!("stdout: {}", str::from_utf8(&output.stdout).unwrap());
        println!("stderr: {}", str::from_utf8(&output.stderr).unwrap());
        return Err(format!("rpm failed with status: {}", output.status));
    }

    let stdout =
        str::from_utf8(&output.stdout).map_err(|e| format!("Invalid UTF-8 output: {}", e))?;

    let mut packages: Vec<Package> = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let name = parts[0].to_string();
            let version = parts[1].to_string();
            let changelog = None;
            packages.push(Package {
                name,
                version,
                changelog,
            });
        } else {
            eprintln!("Warning: Unexpected line format: {}", line);
        }
    }

    Ok(packages)
}

fn package_changes(old_packages: &[Package], new_packages: &[Package]) -> PackageChanges {
    let mut changes = PackageChanges {
        updated: Vec::new(),
        downgraded: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
    };

    let old_map: HashMap<&str, (&str, &Option<String>)> = old_packages
        .iter()
        .map(|p| (p.name.as_str(), (p.version.as_str(), &p.changelog)))
        .collect();

    let new_map: HashMap<&str, (&str, &Option<String>)> = new_packages
        .iter()
        .map(|p| (p.name.as_str(), (p.version.as_str(), &p.changelog)))
        .collect();

    for (name, (new_version, new_changelog)) in new_map.iter() {
        if let Some((old_version, _old_changelog)) = old_map.get(name) {
            let parsed_old_version = Version::parse(old_version);
            let parsed_new_version = Version::parse(new_version);

            match (parsed_old_version, parsed_new_version) {
                (Ok(old), Ok(new)) => match new.cmp(&old) {
                    Ordering::Greater => {
                        changes.updated.push(PackageChange {
                            name: name.to_string(),
                            version_from: old_version.to_string(),
                            version_to: new_version.to_string(),
                            changelog_diff: (**new_changelog).clone(),
                        });
                    }
                    Ordering::Less => {
                        changes.downgraded.push(PackageChange {
                            name: name.to_string(),
                            version_from: old_version.to_string(),
                            version_to: new_version.to_string(),
                            changelog_diff: (**new_changelog).clone(),
                        });
                    }
                    Ordering::Equal => (),
                },
                (Err(_), Ok(_)) => {
                    // Handle cases where the old version is not semver but new is: treat as update.
                    changes.updated.push(PackageChange {
                        name: name.to_string(),
                        version_from: old_version.to_string(),
                        version_to: new_version.to_string(),
                        changelog_diff: (**new_changelog).clone(),
                    });
                }
                (Ok(_), Err(_)) => {
                    // Handle cases where the new version is not semver but old is: treat as downgrade.
                    changes.downgraded.push(PackageChange {
                        name: name.to_string(),
                        version_from: old_version.to_string(),
                        version_to: new_version.to_string(),
                        changelog_diff: (**new_changelog).clone(),
                    });
                }
                (Err(_), Err(_)) => {
                    if new_version != old_version {
                        changes.updated.push(PackageChange {
                            name: name.to_string(),
                            version_from: old_version.to_string(),
                            version_to: new_version.to_string(),
                            changelog_diff: (**new_changelog).clone(),
                        });
                    }
                }
            }
        } else {
            // Package was added
            changes.added.push(Package {
                name: name.to_string(),
                version: new_version.to_string(),
                changelog: (**new_changelog).clone(),
            });
        }
    }

    // Check for removed packages
    for (name, (old_version, old_changelog)) in old_map.iter() {
        if !new_map.contains_key(name) {
            changes.removed.push(Package {
                name: name.to_string(),
                version: old_version.to_string(),
                changelog: (**old_changelog).clone(),
            });
        }
    }

    changes.updated.sort();
    changes.downgraded.sort();
    changes.added.sort();
    changes.removed.sort();

    changes
}

fn print_package_changes(package_changes: &PackageChanges, colored: bool) {
    if !package_changes.updated.is_empty() {
        println!(
            "The following {} packages were upgraded:",
            package_changes.updated.len()
        );
        for pkg in &package_changes.updated {
            let name = if colored {
                &pkg.name.green().to_string()
            } else {
                &pkg.name
            };
            let version_from = if colored {
                &pkg.version_from.white().to_string()
            } else {
                &pkg.version_from
            };
            let version_to = if colored {
                &pkg.version_to.bright_white().to_string()
            } else {
                &pkg.version_to
            };
            println!("  {name} ({version_from} -> {version_to})");
        }
        println!();
    }

    if !package_changes.downgraded.is_empty() {
        println!(
            "The following {} packages were downgraded:",
            package_changes.downgraded.len()
        );
        for pkg in &package_changes.downgraded {
            let name = if colored {
                &pkg.name.yellow().to_string()
            } else {
                &pkg.name
            };
            let version_from = if colored {
                &pkg.version_from.bright_white().to_string()
            } else {
                &pkg.version_from
            };
            let version_to = if colored {
                &pkg.version_to.white().to_string()
            } else {
                &pkg.version_to
            };
            println!("  {name} ({version_from} -> {version_to})");
        }
        println!();
    }

    if !package_changes.added.is_empty() {
        println!(
            "The following {} NEW packages were installed:",
            package_changes.added.len()
        );
        for pkg in &package_changes.added {
            let name = if colored {
                &pkg.name.blue().to_string()
            } else {
                &pkg.name
            };
            let version = if colored {
                &pkg.version.bright_white().to_string()
            } else {
                &pkg.version
            };
            println!("  {name} ({version})");
        }
        println!();
    }

    if !package_changes.removed.is_empty() {
        println!(
            "The following {} packages were REMOVED:",
            package_changes.removed.len()
        );
        for pkg in &package_changes.removed {
            let name = if colored {
                &pkg.name.red().to_string()
            } else {
                &pkg.name
            };
            let version = if colored {
                &pkg.version.bright_white().to_string()
            } else {
                &pkg.version
            };
            println!("  {name} ({version})");
        }
        println!();
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct FileInfo {
    path: String,
    size: u64,
    file_type: FileType,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum FileType {
    File,
    Dir,
    Link,
    Unknown,
}

#[derive(Debug, Serialize)]
struct FileChanges {
    modified: Vec<FileInfo>,
    added: Vec<FileInfo>,
    removed: Vec<FileInfo>,
}

fn get_files_from(snapshot: Option<u32>, dir_path: &str) -> Result<Vec<FileInfo>, std::io::Error> {
    let snapshot_path = snapshot.map(|id| format!("/.snapshots/{id}/snapshot"));
    let path = format!(
        "{}{dir_path}",
        snapshot_path.clone().unwrap_or("".to_string())
    );

    get_files_in_directory_recursive(&path, &snapshot_path)
}

fn get_files_in_directory_recursive(
    dir_path: &str,
    root_path: &Option<String>,
) -> Result<Vec<FileInfo>, std::io::Error> {
    let path = Path::new(dir_path);

    if !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            "Not a directory",
        ));
    }

    let mut file_infos: Vec<FileInfo> = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;

        let relative_path = entry_path
            .strip_prefix(root_path.as_ref().map_or("", |v| v))
            .unwrap_or(&entry_path);
        let full_path = Path::new("/").join(relative_path);

        let size = metadata.len();

        let file_type = if metadata.is_dir() {
            FileType::Dir
        } else if metadata.is_file() {
            FileType::File
        } else if metadata.is_symlink() {
            FileType::Link
        } else {
            FileType::Unknown
        };

        let file_info = FileInfo {
            path: full_path.to_string_lossy().to_string(),
            size,
            file_type,
        };

        if entry_path.is_dir() {
            let subdir_files =
                get_files_in_directory_recursive(entry_path.to_str().unwrap(), root_path)?;
            file_infos.extend(subdir_files);
        } else {
            file_infos.push(file_info);
        }
    }

    Ok(file_infos)
}

fn file_changes(old_files: &[FileInfo], new_files: &[FileInfo]) -> FileChanges {
    let mut changes = FileChanges {
        modified: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
    };

    let old_map: HashMap<&str, &FileInfo> =
        old_files.iter().map(|f| (f.path.as_str(), f)).collect();
    let new_map: HashMap<&str, &FileInfo> =
        new_files.iter().map(|f| (f.path.as_str(), f)).collect();

    for (name, new_file) in &new_map {
        if let Some(old_file) = old_map.get(name) {
            if new_file.size != old_file.size
                || new_file.file_type != old_file.file_type
            {
                changes.modified.push((**new_file).clone());
            }
        } else {
            changes.added.push((**new_file).clone());
        }
    }

    for (name, old_file) in &old_map {
        if !new_map.contains_key(name) {
            changes.removed.push((**old_file).clone());
        }
    }

    changes.modified.sort();
    changes.added.sort();
    changes.removed.sort();

    changes
}

fn print_file_changes(file_changes: &FileChanges, colored: bool) {
    if !file_changes.modified.is_empty() {
        println!(
            "The following {} file were modified:",
            file_changes.modified.len()
        );
        for f in &file_changes.modified {
            let path = if colored {
                &f.path.green().to_string()
            } else {
                &f.path
            };
            println!("  {path}");
        }
        println!();
    }

    if !file_changes.added.is_empty() {
        println!(
            "The following {} NEW files were created:",
            file_changes.added.len()
        );
        for f in &file_changes.added {
            let path = if colored {
                &f.path.blue().to_string()
            } else {
                &f.path
            };
            println!("  {path}");
        }
        println!();
    }

    if !file_changes.removed.is_empty() {
        println!(
            "The following {} files were REMOVED:",
            file_changes.removed.len()
        );
        for f in &file_changes.removed {
            let path = if colored {
                &f.path.red().to_string()
            } else {
                &f.path
            };
            println!("  {path}");
        }
        println!();
    }
}

#[derive(Debug)]
enum AppError {
    Io(std::io::Error),
    String(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "IO Error: {}", err),
            AppError::String(err) => write!(f, "String Error: {}", err),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AppError::Io(err) => Some(err),
            AppError::String(_) => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        AppError::Io(value)
    }
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        AppError::String(value)
    }
}

impl From<&str> for AppError {
    fn from(value: &str) -> Self {
        AppError::String(value.to_string())
    }
}

fn cmd_list(_cli: &Cli) -> Result<(), AppError> {
    eprintln!("Command not implemented!");
    // sudo snapper --jsonout --no-dbus ls --disable-used-space
    Ok(())
}

#[derive(Debug, Serialize)]
struct Changes {
    packages: PackageChanges,
    files: FileChanges,
}

fn cmd_diff(cli: &Cli) -> Result<(), AppError> {
    if cli.old_snapshot.is_none() {
        return Err("Missing old snapshot parameter".into());
    };

    check_directory_exists_and_readable("/.snapshots")?;

    let mut pkg_changes: Option<PackageChanges> = None;
    let mut etc_changes: Option<FileChanges> = None;

    if cli.packages || !cli.etc {
        let old_packages = get_packages_from(cli.old_snapshot)?;
        let new_packages = get_packages_from(cli.new_snapshot)?;

        pkg_changes = Some(package_changes(&old_packages, &new_packages));
    }

    if cli.etc || !cli.packages {
        let old_files = get_files_from(cli.old_snapshot, "/etc")?;
        let new_files = get_files_from(cli.new_snapshot, "/etc")?;

        etc_changes = Some(file_changes(&old_files, &new_files));
    }

    match (pkg_changes, etc_changes) {
        (Some(pkg), Some(etc)) => {
            if cli.json {
                let changes = Changes {
                    packages: pkg,
                    files: etc,
                };
                println!("{}", serde_json::to_string(&changes).unwrap());
            } else {
                print_package_changes(&pkg, !cli.no_colors);
                print_file_changes(&etc, !cli.no_colors);
            }
        }
        (Some(pkg), None) => {
            if cli.json {
                println!("{}", serde_json::to_string(&pkg).unwrap());
            } else {
                print_package_changes(&pkg, !cli.no_colors);
            }
        }
        (None, Some(etc)) => {
            if cli.json {
                println!("{}", serde_json::to_string(&etc).unwrap());
            } else {
                print_file_changes(&etc, !cli.no_colors);
            }
        }
        (None, None) => {}
    }

    Ok(())
}

fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::List) => cmd_list(&cli),
        None => cmd_diff(&cli),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_package_changes() {
        let old_packages = vec![
            Package {
                name: "package_a".to_string(),
                version: "1.0.0".to_string(),
                changelog: None,
            },
            Package {
                name: "package_b".to_string(),
                version: "1.1.0".to_string(),
                changelog: None,
            },
            Package {
                name: "package_c".to_string(),
                version: "1.0.0".to_string(),
                changelog: None,
            },
        ];

        let new_packages = vec![
            Package {
                name: "package_a".to_string(),
                version: "1.1.0".to_string(),
                changelog: None,
            },
            Package {
                name: "package_b".to_string(),
                version: "1.0.0".to_string(),
                changelog: None,
            },
            Package {
                name: "package_d".to_string(),
                version: "1.0.0".to_string(),
                changelog: None,
            },
        ];

        let changes = package_changes(&old_packages, &new_packages);

        assert_eq!(changes.updated.len(), 1);
        assert_eq!(changes.updated[0].name, "package_a");
        assert_eq!(changes.updated[0].version_from, "1.0.0".to_string());
        assert_eq!(changes.updated[0].version_to, "1.1.0".to_string());

        assert_eq!(changes.downgraded.len(), 1);
        assert_eq!(changes.downgraded[0].name, "package_b");
        assert_eq!(changes.downgraded[0].version_from, "1.1.0".to_string());
        assert_eq!(changes.downgraded[0].version_to, "1.0.0".to_string());

        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].name, "package_d");
        assert_eq!(changes.added[0].version, "1.0.0".to_string());

        assert_eq!(changes.removed.len(), 1);
        assert_eq!(changes.removed[0].name, "package_c");
        assert_eq!(changes.removed[0].version, "1.0.0".to_string());
    }

    #[test]
    fn test_get_files_in_directory_recursive() -> Result<(), std::io::Error> {
        // Create a temporary directory structure for testing
        std::fs::create_dir_all("test_dir/subdir1/subdir2")?;
        File::create("test_dir/file1.txt")?;
        File::create("test_dir/subdir1/file2.txt")?;
        File::create("test_dir/subdir1/subdir2/file3.txt")?;

        let files = get_files_in_directory_recursive("test_dir", &None)?;
        assert_eq!(files.len(), 3);
        // assert!(files.contains(&"file1.txt".to_string()));
        // assert!(files.contains(&"file2.txt".to_string()));
        // assert!(files.contains(&"file3.txt".to_string()));

        std::fs::remove_dir_all("test_dir")?; // Clean up

        Ok(())
    }

    #[test]
    fn test_get_files_in_directory_recursive_not_a_directory() {
        let result = get_files_in_directory_recursive("not_a_directory", &None); // Nonexistent path
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::NotADirectory);
        }
    }
}
