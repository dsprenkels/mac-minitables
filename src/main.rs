#![allow(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate sha2;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate regex;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;

mod table;

use std::fmt;
use std::fs::{read_dir, File, OpenOptions};
use std::io::prelude::*;

use regex::Regex;
use sha2::{Digest, Sha256};

#[derive(Debug)]
enum ParseError {
    BadLength(usize),
    ParseIntError,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ParseError::BadLength(len) => write!(f, "bad hash length ({})", len),
            ParseError::ParseIntError => write!(f, "invalid character in hash"),
        }
    }
}

fn prefix_to_filename(prefix: &[u8; 3]) -> std::ffi::OsString {
    std::ffi::OsString::from(format!(
        "{:02X}{:02X}{:02X}.dat",
        prefix[0], prefix[1], prefix[2]
    ))
}

/// Load all the MAC address prefixes from the provided input file in `filename`.
///
/// If filename is "-", the prefixes are read from stdin. Provide "./-" to this function if you
/// want to read from the "-" file in the current directory.
fn load_prefixes(filename: &std::ffi::OsStr) -> Result<Vec<[u8; 3]>, Box<std::error::Error>> {
    let stdin;
    let reader: Box<BufRead> = if filename == std::ffi::OsStr::new("-") {
        stdin = std::io::stdin();
        Box::new(stdin.lock())
    } else {
        let file = File::open(filename)?;
        Box::new(std::io::BufReader::new(file))
    };

    let mut prefixes = Vec::new();
    for line_result in reader.lines() {
        let line = line_result.unwrap();
        if let Ok(limbs) = parse_prefix(&line) {
            prefixes.push(limbs);
        }
    }
    prefixes.sort_unstable();
    prefixes.dedup();
    info!("Parsed {} different prefixes", prefixes.len());
    Ok(prefixes)
}

fn parse_address(address_str: &str) -> Result<table::MACAddress, ParseError> {
    lazy_static! {
        static ref RES: [Regex; 3] = [
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2})-([A-Za-z0-9]{2})-([A-Za-z0-9]{2})-([A-Za-z0-9]{2})-([A-Za-z0-9]{2})-([A-Za-z0-9]{2})\b").unwrap(),
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2}):([A-Za-z0-9]{2}):([A-Za-z0-9]{2}):([A-Za-z0-9]{2}):([A-Za-z0-9]{2}):([A-Za-z0-9]{2})\b").unwrap(),
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2})([A-Za-z0-9]{2})([A-Za-z0-9]{2})([A-Za-z0-9]{2})([A-Za-z0-9]{2})([A-Za-z0-9]{2})\b").unwrap(),
        ];
    }
    for re in RES.iter() {
        let word = match re.find(address_str) {
            Some(m) => &address_str[m.start()..m.end()],
            None => continue,
        };
        debug!("Trying to parse {}", word);
        let caps = re.captures(&word).unwrap();
        let mut limbs = [0_u8; 6];
        for (idx, cap_idx) in (1..=6).enumerate() {
            limbs[idx] = match u8::from_str_radix(caps.get(cap_idx).unwrap().as_str(), 16) {
                Ok(x) => x,
                Err(_) => unreachable!("Failed to parse digit {}", word),
            };
        }
        let addr = table::MACAddress::from(&limbs);
        debug!("Parsed MAC address: {}", addr);
        return Ok(addr);
    }
    Err(ParseError::ParseIntError)
}

fn parse_prefix(prefix_str: &str) -> Result<[u8; 3], ParseError> {
    lazy_static! {
        static ref RES: [Regex; 3] = [
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2})-([A-Za-z0-9]{2})-([A-Za-z0-9]{2})\b").unwrap(),
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2}):([A-Za-z0-9]{2}):([A-Za-z0-9]{2})\b").unwrap(),
            Regex::new(r"(?-u)\b([A-Za-z0-9]{2})([A-Za-z0-9]{2})([A-Za-z0-9]{2})\b").unwrap(),
        ];
    }
    for re in RES.iter() {
        let word = match re.find(prefix_str) {
            Some(m) => &prefix_str[m.start()..m.end()],
            None => continue,
        };
        debug!("Trying to parse {}", word);
        let caps = re.captures(&word).unwrap();
        let mut limbs = [0_u8; 3];
        for (idx, cap_idx) in (1..=3).enumerate() {
            limbs[idx] = match u8::from_str_radix(caps.get(cap_idx).unwrap().as_str(), 16) {
                Ok(x) => x,
                Err(_) => unreachable!("Failed to parse digit {}", word),
            };
        }
        debug!(
            "Parsed MAC prefix: {:02X}:{:02X}:{:02X}",
            limbs[0], limbs[1], limbs[2]
        );
        return Ok(limbs);
    }
    Err(ParseError::ParseIntError)
}

fn parse_hash(hash_str: &str) -> Result<[u8; 32], ParseError> {
    if hash_str.len() != 64 {
        return Err(ParseError::BadLength(hash_str.len()));
    }

    let mut buf: [u8; 32] = [0; 32];
    for idx in 0..32 {
        buf[idx] = match u8::from_str_radix(&hash_str[2 * idx..2 * idx + 2], 16) {
            Ok(b) => b,
            Err(_) => return Err(ParseError::ParseIntError),
        };
    }
    Ok(buf)
}

fn main_compute(_app_m: &clap::ArgMatches, sub_m: &clap::ArgMatches) {
    let prefix_file = sub_m
        .value_of_os("prefix_file")
        .expect("no prefix file provided");
    let table_dir = sub_m
        .value_of_os("table_dir")
        .expect("no table dir provided");
    let prefixes = load_prefixes(prefix_file).unwrap();

    for prefix in prefixes {
        let filename = prefix_to_filename(&prefix);
        let path = std::path::Path::new(table_dir).join(filename);
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => {
                info!(
                    "Computing table for prefix: {:02X}:{:02X}:{:02X}",
                    prefix[0], prefix[1], prefix[2]
                );
                let mut writer = std::io::BufWriter::new(file);
                table::compute(&prefix, &mut writer).unwrap();
            }
            Err(err) => {
                error!("Opening {:?} failed: {}", path, err);
            }
        }
    }
}

fn main_lookup(_app_m: &clap::ArgMatches, sub_m: &clap::ArgMatches) {
    let table_dir = sub_m
        .value_of_os("table_dir")
        .expect("no table dir provided");
    let hash_str = sub_m
        .value_of("HASH")
        .expect("no MAC address hash provided");
    let hash = match parse_hash(hash_str) {
        Ok(buf) => buf,
        Err(err) => panic!(err),
    };

    // Parse the hash
    info!("Parsed hash: {:?}", hash);

    // Read all lists and find the preimage
    let entries = read_dir(table_dir).unwrap();
    'table_file: for entry in entries {
        let file = match entry {
            Ok(x) => x,
            Err(e) => {
                error!("{}", e);
                continue;
            }
        };
        if !file.file_type().map(|x| x.is_file()).unwrap_or(false) {
            continue 'table_file;
        }
        let file_name = file.file_name();
        let mut prefix: [u8; 3] = [0; 3];
        let file_name_no_os = file_name.as_os_str().to_string_lossy();
        for idx in 0..3 {
            prefix[idx] = match u8::from_str_radix(&file_name_no_os[2 * idx..2 * idx + 2], 16) {
                Ok(b) => b,
                Err(e) => {
                    error!("{}", e);
                    continue 'table_file;
                }
            };
        }

        let path = &file.path();
        match OpenOptions::new().read(true).open(path) {
            Ok(f) => {
                info!(
                    "Searching for preimages in file: {}",
                    path.to_string_lossy()
                );
                let mut reader = std::io::BufReader::new(f);
                let preimage = match table::lookup(&hash, &prefix, reader) {
                    Ok(Some(x)) => x,
                    Ok(None) => {
                        debug!("No preimage found in {}", path.to_string_lossy());
                        continue 'table_file;
                    }
                    Err(e) => {
                        error!("{}", e);
                        continue 'table_file;
                    }
                };
                info!("PREIMAGE FOUND");
                println!("{}", preimage);
                return;
            }
            Err(err) => {
                error!("Opening {} failed: {}", path.to_string_lossy(), err);
                continue 'table_file;
            }
        }
    }
}

fn main_hash(_app_m: &clap::ArgMatches, sub_m: &clap::ArgMatches) {
    let addr_str = sub_m
        .value_of("ADDRESS")
        .expect("no address string provided");
    let addr = match parse_address(addr_str) {
        Ok(x) => x,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };

    let mut hasher = Sha256::new();
    hasher.input(addr.into_array());
    let hash = hasher.result_reset();
    for b in hash {
        print!("{:02x}", b);
    }
    println!();
}

fn main() {
    env_logger::init();
    let app = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .setting(clap::AppSettings::SubcommandRequired)
        .subcommand(
            clap::SubCommand::with_name("compute")
                .about("Compute lookup tables")
                .arg(
                    clap::Arg::with_name("table_dir")
                        .short("d")
                        .long("table-dir")
                        .value_name("DIR")
                        .help("Set the directory storing the tables")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    clap::Arg::with_name("prefix_file")
                        .value_name("PREFIX_FILE")
                        .help("Provides a file of all the prefix tables to compute")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    clap::Arg::with_name("force")
                        .short("f")
                        .long("force")
                        .help("Overwrite any lookup tables that already exist"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("lookup")
                .about("Find a MAC address preimage")
                .arg(
                    clap::Arg::with_name("table_dir")
                        .short("d")
                        .long("table-dir")
                        .value_name("DIR")
                        .help("Set the directory storing the tables")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::with_name("HASH")
                        .help("The hash of the MAC-address that needs to be found")
                        .required(true),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("hash")
                .about("Hash a MAC address")
                .arg(
                    clap::Arg::with_name("ADDRESS")
                        .help("The MAC-address that needs to be hashed")
                        .required(true),
                ),
        );
    let app_m = &app.get_matches();
    match app_m.subcommand() {
        ("compute", Some(sub_m)) => main_compute(app_m, sub_m),
        ("lookup", Some(sub_m)) => main_lookup(app_m, sub_m),
        ("hash", Some(sub_m)) => main_hash(app_m, sub_m),
        _ => unreachable!(),
    }
}
