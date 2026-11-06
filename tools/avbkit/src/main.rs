//! `avbkit` — host commands over the AOSP AVB format.
//!
//! The tool reads and writes files that the caller names. It does not open a
//! block device, does not scan for a device and does not sign an image.
//!
//! Commands:
//!
//! * `inspect <image>`: print the header, the descriptors and the key of one
//!   vbmeta image or of the metadata a footer locates.
//! * `extract <image> [--out <file>]`: write the vbmeta extent that the image's
//!   footer locates.
//! * `verify-chain --key <blob> <root> [images...]`: walk the root and every
//!   image it chains, and verify each metadata signature against an explicit
//!   trusted key set.
//! * `graft <image> --metadata <file> --out <file>`: replace the metadata and
//!   the footer at the stock metadata offset.
//! * `place <image> --metadata <file> --placement <keep|tail|at:OFFSET> --out
//!   <file>`: move the metadata to a new placement and write the full image.

#![forbid(unsafe_code)]

use std::env;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use avb_chain::{HashAlg, KeyBlob, Plan, Verdict, extract_vbmd};
use avb_format::{
    FOOTER_SIZE, VBMETA_MAX_SIZE, exact_metadata, parse_footer, validate_key_blob, validate_vbmeta,
};
use avb_graft::plan_graft;
use avb_image::{Extent, PayloadHeader, Placement, materialize, plan as plan_placement};

type Res<T> = Result<T, CliError>;

/// One command failure, with the message the caller sees.
#[derive(Debug)]
enum CliError {
    Message(String),
    Io(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Turn any displayable library error into a command failure.
fn at<E: fmt::Display>(error: E) -> CliError {
    CliError::Message(error.to_string())
}

fn message<T>(text: impl Into<String>) -> Res<T> {
    Err(CliError::Message(text.into()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn algorithm_name(value: u32) -> &'static str {
    match value {
        0 => "NONE",
        1 => "SHA256_RSA2048",
        2 => "SHA256_RSA4096",
        3 => "SHA256_RSA8192",
        4 => "SHA512_RSA2048",
        5 => "SHA512_RSA4096",
        6 => "SHA512_RSA8192",
        7 => "ML_DSA_65",
        8 => "ML_DSA_87",
        _ => "UNKNOWN",
    }
}

fn key_line(blob: &[u8]) -> String {
    match validate_key_blob(blob) {
        Some(bits) => format!("{bits} bits, sha256 {}", hex(&avb_chain::sha256(blob))),
        None => "not a valid AVB RSA public key blob".to_string(),
    }
}

fn read_bounded(path: &Path, limit: u64) -> Res<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return message(format!(
            "{} is larger than the {limit}-byte limit",
            path.display()
        ));
    }
    Ok(bytes)
}

/// The metadata extent of an image: the whole file for `AVB0`, else the
/// extent its 64-byte footer locates.
fn metadata_of(bytes: &[u8]) -> Res<(u64, u64, &[u8])> {
    if bytes.starts_with(b"AVB0") {
        let exact = exact_metadata(bytes).map_err(at)?;
        return Ok((0, exact.len() as u64, exact));
    }
    if bytes.len() < FOOTER_SIZE {
        return message("image is shorter than its 64-byte footer");
    }
    let footer_bytes = &bytes[bytes.len() - FOOTER_SIZE..];
    let footer = parse_footer(footer_bytes, bytes.len() as u64).map_err(at)?;
    let start = usize::try_from(footer.vbmeta_offset)
        .map_err(|_| CliError::Message("metadata offset does not fit this host".into()))?;
    let size = usize::try_from(footer.vbmeta_size)
        .map_err(|_| CliError::Message("metadata size does not fit this host".into()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| CliError::Message("metadata extent overflows the host size".into()))?;
    let metadata = bytes
        .get(start..end)
        .ok_or_else(|| CliError::Message("footer metadata extent is outside the image".into()))?;
    Ok((footer.vbmeta_offset, footer.vbmeta_size, metadata))
}

// ----------------------------------------------------------------- inspect

fn cmd_inspect(args: &[String]) -> Res<()> {
    let [path] = args else {
        return message("usage: avbkit inspect <image>");
    };
    let bytes = read_bounded(Path::new(path), VBMETA_MAX_SIZE * 64)?;
    let image_size = bytes.len() as u64;
    let (offset, declared, metadata) = metadata_of(&bytes)?;
    let info = avb_format::inspect(metadata).map_err(at)?;

    println!("image={path}");
    println!("image_size={image_size}");
    println!(
        "kind={}",
        if bytes.starts_with(b"AVB0") {
            "vbmeta"
        } else {
            "footered"
        }
    );
    println!("metadata_offset={offset}");
    println!("metadata_declared_size={declared}");
    println!("metadata_size={}", info.size);
    println!(
        "header.algorithm={} ({})",
        info.header.algorithm,
        algorithm_name(info.header.algorithm)
    );
    println!("header.auth_size={}", info.header.auth_size);
    println!("header.aux_size={}", info.header.aux_size);
    println!("header.hash_size={}", info.header.hash_size);
    println!("header.signature_size={}", info.header.signature_size);
    println!("header.rollback_index={}", info.header.rollback_index);
    println!("header.flags={:#x}", info.header.flags);
    println!("key={}", key_line(info.public_key));

    for descriptor in info.descriptors.clone() {
        match descriptor.map_err(at)? {
            avb_format::Descriptor::Property(property) => {
                println!("property={} value={}", property.key, property.value);
            }
            avb_format::Descriptor::Hash(hash) => {
                println!(
                    "hash.partition={} image_size={} algorithm={} digest={}",
                    hash.partition_name,
                    hash.image_size,
                    hash.hash_algorithm,
                    hex(hash.digest)
                );
            }
            avb_format::Descriptor::Hashtree(tree) => {
                println!(
                    "hashtree.partition={} image_size={} tree_offset={} tree_size={} algorithm={} root_digest={}",
                    tree.partition_name,
                    tree.image_size,
                    tree.tree_offset,
                    tree.tree_size,
                    tree.hash_algorithm,
                    hex(tree.root_digest)
                );
            }
            avb_format::Descriptor::KernelCmdline(cmdline) => {
                println!(
                    "kernel_cmdline.flags={} cmdline={}",
                    cmdline.flags, cmdline.cmdline
                );
            }
            avb_format::Descriptor::ChainPartition(chain) => {
                println!(
                    "chain.partition={} rollback_index_location={} key={}",
                    chain.name,
                    chain.rollback_index_location,
                    key_line(chain.public_key)
                );
            }
            avb_format::Descriptor::Unknown { tag, body } => {
                println!("unknown_descriptor.tag={} size={}", tag, body.len());
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------------- extract

fn cmd_extract(args: &[String]) -> Res<()> {
    let mut image = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                index += 1;
                out = Some(
                    args.get(index)
                        .ok_or_else(|| CliError::Message("--out needs a path".into()))?
                        .clone(),
                );
            }
            flag if flag.starts_with("--") => {
                return message(format!("unknown option {flag}"));
            }
            path => {
                if image.is_some() {
                    return message("usage: avbkit extract <image> [--out <file>]");
                }
                image = Some(PathBuf::from(path));
            }
        }
        index += 1;
    }
    let image = image
        .ok_or_else(|| CliError::Message("usage: avbkit extract <image> [--out <file>]".into()))?;

    let size = fs::metadata(&image)?.len();
    let mut file = fs::File::open(&image)?;
    let mut reader = |offset: u64, out: &mut [u8]| -> Result<(), std::io::Error> {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    };
    let metadata = extract_vbmd(size, &mut reader).map_err(at)?;
    validate_vbmeta(&metadata).map_err(at)?;
    match out {
        Some(path) => {
            fs::write(Path::new(&path), &metadata)?;
            eprintln!(
                "wrote {path} metadata_size={} sha256={}",
                metadata.len(),
                hex(&avb_chain::sha256(&metadata))
            );
        }
        None => {
            std::io::stdout().write_all(&metadata)?;
            eprintln!(
                "metadata_size={} sha256={}",
                metadata.len(),
                hex(&avb_chain::sha256(&metadata))
            );
        }
    }
    Ok(())
}

// ------------------------------------------------------------ verify-chain

/// Split `NAME=PATH` into its parts; a plain path has no explicit name.
fn split_name(argument: &str) -> (Option<String>, PathBuf) {
    match argument.split_once('=') {
        Some((name, path)) if !name.is_empty() && !path.is_empty() => {
            (Some(name.to_string()), PathBuf::from(path))
        }
        _ => (None, PathBuf::from(argument)),
    }
}

/// Candidate partition names for a path, most specific first.
fn candidate_names(path: &Path) -> Vec<String> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let stem = name.split('.').next().unwrap_or(name).to_string();
    let mut names = vec![stem.clone()];
    for suffix in ["_a", "_b"] {
        if let Some(base) = stem.strip_suffix(suffix) {
            names.push(base.to_string());
        }
    }
    names
}

fn cmd_verify_chain(args: &[String]) -> Res<bool> {
    let mut keys: Vec<KeyBlob> = Vec::new();
    let mut images: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                index += 1;
                let path = args
                    .get(index)
                    .ok_or_else(|| CliError::Message("--key needs a blob path".into()))?;
                let blob = fs::read(path)?;
                keys.push(KeyBlob::from_bytes(&blob).map_err(at)?);
            }
            flag if flag.starts_with("--") => return message(format!("unknown option {flag}")),
            value => images.push(value.to_string()),
        }
        index += 1;
    }
    if keys.is_empty() || images.is_empty() {
        return message("usage: avbkit verify-chain --key <blob> <root> [NAME=]image...");
    }

    let (root_explicit, root_path) = split_name(&images[0]);
    let root_bytes = read_bounded(&root_path, VBMETA_MAX_SIZE * 64)?;
    let (_, _, root_metadata) = metadata_of(&root_bytes)?;
    if root_explicit.is_some() {
        return message("the root takes no NAME=PATH prefix");
    }
    let mut plan = Plan::with_trusted_keys(root_metadata, &keys).map_err(at)?;
    println!("root={}", root_path.display());
    println!(
        "root.algorithm={} ({})",
        plan.root_algorithm(),
        algorithm_name(plan.root_algorithm())
    );
    println!("root.verdict={}", plan.root_verdict());

    let mut failed = 0usize;
    for argument in &images[1..] {
        let (explicit, path) = split_name(argument);
        let needed: Vec<String> = plan.needs().into_iter().map(|need| need.name).collect();
        let name = match explicit {
            Some(name) => name,
            None => candidate_names(&path)
                .into_iter()
                .find(|candidate| needed.iter().any(|need| need == candidate))
                .ok_or_else(|| {
                    CliError::Message(format!(
                        "{} matches no demanded partition; pass NAME=PATH (demanded: {})",
                        path.display(),
                        needed.join(", ")
                    ))
                })?,
        };
        let mut file = fs::File::open(&path)?;
        let size = file.metadata()?.len();
        let mut reader = |offset: u64, out: &mut [u8]| -> Result<(), std::io::Error> {
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(out)
        };
        match plan.supply_from(&name, size, &mut reader) {
            Ok(accepted) => println!(
                "supplied={} trusted={} metadata_size={} key_sha256={}",
                accepted.name,
                accepted.trusted,
                accepted.metadata_len,
                hex(&accepted.key_sha256)
            ),
            Err(rejected) => {
                failed += 1;
                println!("rejected={} verdict={}", rejected.name, rejected.verdict);
            }
        }
    }

    let missing = plan.missing();
    if !missing.is_empty() {
        println!("missing={}", missing.join(","));
    }
    let digest = plan.vbmeta_digest_with(HashAlg::Sha256);
    println!(
        "metadata.sha256={} metadata.size={}",
        digest.hex(),
        digest.total_size
    );
    match plan.libavb_cmdline_digest() {
        Some(cmdline) => println!("cmdline.digest={}:{}", cmdline.name(), cmdline.hex()),
        None => println!("cmdline.digest=none"),
    }

    let trusted = matches!(plan.root_verdict(), Verdict::Verified { trusted: true, .. });
    let complete = plan.complete();
    println!("complete={complete} trusted={trusted}");
    Ok(failed == 0 && complete && trusted)
}

// ------------------------------------------------------------------- graft

fn cmd_graft(args: &[String]) -> Res<()> {
    let mut image = None;
    let mut metadata_path = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--metadata" => {
                index += 1;
                metadata_path =
                    Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        CliError::Message("--metadata needs a path".into())
                    })?));
            }
            "--out" => {
                index += 1;
                out =
                    Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        CliError::Message("--out needs a path".into())
                    })?));
            }
            flag if flag.starts_with("--") => return message(format!("unknown option {flag}")),
            path => {
                if image.replace(PathBuf::from(path)).is_some() {
                    return message("usage: avbkit graft <image> --metadata <file> --out <file>");
                }
            }
        }
        index += 1;
    }
    let (Some(image), Some(metadata_path), Some(out)) = (image, metadata_path, out) else {
        return message("usage: avbkit graft <image> --metadata <file> --out <file>");
    };

    let original = fs::read(&image)?;
    if original.len() < FOOTER_SIZE {
        return message("image is shorter than its 64-byte footer");
    }
    let metadata = fs::read(&metadata_path)?;
    let footer_bytes = &original[original.len() - FOOTER_SIZE..];
    let graft = plan_graft(original.len() as u64, footer_bytes, &metadata).map_err(at)?;
    let mut grafted = vec![0u8; original.len()];
    graft
        .read(0, &mut grafted, |offset, out| {
            let start = offset as usize;
            out.copy_from_slice(&original[start..start + out.len()]);
            Ok::<(), CliError>(())
        })
        .map_err(|error| CliError::Message(format!("{error:?}")))?;
    fs::write(&out, &grafted)?;
    println!(
        "wrote {} image_size={} metadata_offset={} metadata_size={} footer_offset={}",
        out.display(),
        graft.image_size(),
        graft.metadata_offset(),
        graft.metadata().len(),
        graft.footer_offset()
    );
    Ok(())
}

// ------------------------------------------------------------------- place

fn parse_placement(value: &str) -> Res<Placement> {
    match value {
        "keep" => Ok(Placement::KeepOriginal),
        "tail" => Ok(Placement::Tail),
        other => match other.strip_prefix("at:") {
            Some(offset) => Ok(Placement::At(offset.parse().map_err(|_| {
                CliError::Message(format!("{offset} is not a metadata offset"))
            })?)),
            None => message("placement must be keep, tail or at:OFFSET"),
        },
    }
}

fn parse_extent(value: &str) -> Res<Extent> {
    match value {
        "footer" => Ok(Extent::Footer),
        "zero" => Ok(Extent::ZeroTail),
        "boot" => Ok(Extent::Header(PayloadHeader::AndroidBoot)),
        "dtbo" => Ok(Extent::Header(PayloadHeader::DtboTable)),
        other => match other.strip_prefix("known:") {
            Some(end) => Ok(Extent::Known(end.parse().map_err(|_| {
                CliError::Message(format!("{end} is not a payload end"))
            })?)),
            None => message("extent must be footer, zero, boot, dtbo or known:END"),
        },
    }
}

fn cmd_place(args: &[String]) -> Res<()> {
    let mut image = None;
    let mut metadata = None;
    let mut placement = Placement::Tail;
    let mut extent = Extent::Footer;
    let mut block_size = avb_image::BLOCK_SIZE;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let mut value = || -> Res<&String> {
            index += 1;
            args.get(index)
                .ok_or_else(|| CliError::Message(format!("{flag} needs a value")))
        };
        match flag {
            "--image" => image = Some(PathBuf::from(value()?)),
            "--metadata" => metadata = Some(PathBuf::from(value()?)),
            "--placement" => placement = parse_placement(value()?)?,
            "--extent" => extent = parse_extent(value()?)?,
            "--block-size" => {
                block_size = value()?
                    .parse()
                    .map_err(|_| CliError::Message("block size must be a number".into()))?
            }
            "--out" => out = Some(PathBuf::from(value()?)),
            other => return message(format!("unknown option {other}")),
        }
        index += 1;
    }
    let (Some(image), Some(metadata), Some(out)) = (image, metadata, out) else {
        return message(
            "usage: avbkit place --image <file> --metadata <file> --placement <keep|tail|at:OFFSET> [--extent footer|zero|boot|dtbo|known:END] [--block-size N] --out <file>",
        );
    };

    let original = fs::read(&image)?;
    let metadata = fs::read(&metadata)?;
    let planned = plan_placement(
        placement,
        extent,
        original.len() as u64,
        block_size,
        &metadata,
        |offset, out| {
            let start = offset as usize;
            out.copy_from_slice(&original[start..start + out.len()]);
            Ok::<(), CliError>(())
        },
    )
    .map_err(at)?;
    let placed = materialize(&original, &planned).map_err(at)?;
    fs::write(&out, &placed)?;
    println!(
        "wrote {} placement={:?} evidence={:?} image_size={} payload_size={} metadata_offset={} metadata_size={} footer_offset={}",
        out.display(),
        planned.placement,
        planned.evidence,
        planned.image_size,
        planned.original_image_size,
        planned.metadata.offset,
        planned.metadata.bytes.len(),
        planned.footer.offset
    );
    Ok(())
}

// -------------------------------------------------------------------- main

fn usage() -> &'static str {
    "usage: avbkit <inspect|extract|verify-chain|graft|place> [arguments]\n\
     \n\
     inspect <image>\n\
     extract <image> [--out <file>]\n\
     verify-chain --key <blob> <root> [NAME=]image...\n\
     graft <image> --metadata <file> --out <file>\n\
     place --image <file> --metadata <file> --placement <keep|tail|at:OFFSET> [--extent ...] --out <file>"
}

fn run() -> Res<bool> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        return message(usage());
    };
    match command.as_str() {
        "inspect" => cmd_inspect(rest).map(|()| true),
        "extract" => cmd_extract(rest).map(|()| true),
        "verify-chain" => cmd_verify_chain(rest),
        "graft" => cmd_graft(rest).map(|()| true),
        "place" => cmd_place(rest).map(|()| true),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(true)
        }
        other => message(format!("unknown command {other}\n{}", usage())),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("avbkit: {error}");
            ExitCode::FAILURE
        }
    }
}
