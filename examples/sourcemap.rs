use object::Object;
use std::{env, fs, process};

fn main() {
    let mut args = env::args().skip(1);
    if args.len() == 0 {
        eprintln!(
            "Usage: {} <file> [address] ...",
            env::args().next().unwrap()
        );
        process::exit(1);
    }

    let file_path = args.next().unwrap();
    let file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
    let file = match unsafe { memmap::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            println!("Failed to map file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
    let file = match object::File::parse(&*file) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to parse file '{}': {}", file_path, err);
            process::exit(1);
        }
    };

    let map = file.source_map();

    if args.len() == 0 {
        for symbol in map.symbols() {
            print_symbol(symbol, &map);
        }
    } else {
        for arg in args {
            let address = parse_uint_from_hex_string(&arg);
            if let Some(symbol) = map.get(address) {
                print_symbol(symbol, &map);
            } else {
                println!("{:} not found", address);
            }
        }
    }
}

fn parse_uint_from_hex_string(string: &str) -> u64 {
    if string.len() > 2 && string.starts_with("0x") {
        u64::from_str_radix(&string[2..], 16).expect("Failed to parse address")
    } else {
        u64::from_str_radix(string, 16).expect("Failed to parse address")
    }
}

fn print_symbol(symbol: &object::SourceMapEntry<'_>, map: &object::SourceMap<'_>) {
    println!(
        "{:x} {:x} {} {} {}",
        symbol.address(),
        symbol.size(),
        symbol.name(),
        symbol.source(map).unwrap_or("-"),
        symbol.object(map).unwrap_or("-"),
    );
}
