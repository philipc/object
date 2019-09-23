use std::{env, fs, process};

use object::target_lexicon::{Architecture, BinaryFormat};
use object::{write, SymbolKind, SymbolScope};

fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        eprintln!("Usage: {} <outfile>", args.next().unwrap());
        process::exit(1);
    }

    args.next();
    let out_file_path = args.next().unwrap();

    let mut out_object = write::Object::new(BinaryFormat::Macho, Architecture::X86_64);
    out_object.mangling = write::Mangling::None;

    let section_id = out_object.section_id(write::StandardSection::UninitializedData);
    let out_section = out_object.section_mut(section_id);
    out_section.append_bss(100_000_000_000_000, 1);
    let out_symbol = write::Symbol {
        name: b"my_data".to_vec(),
        value: 0,
        size: 100_000_000_000_000,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: Some(section_id),
    };
    out_object.add_symbol(out_symbol);

    let out_data = out_object.write().unwrap();
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}
