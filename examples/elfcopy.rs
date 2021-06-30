use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::{env, fs, process};

use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, Sym};
use object::Endianness;

fn main() {
    let mut args = env::args();
    if args.len() != 3 {
        eprintln!("Usage: {} <infile> <outfile>", args.next().unwrap());
        process::exit(1);
    }

    args.next();
    let in_file_path = args.next().unwrap();
    let out_file_path = args.next().unwrap();

    let in_file = match fs::File::open(&in_file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_data = match unsafe { memmap2::Mmap::map(&in_file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to parse file: {}", err);
            process::exit(1);
        }
    };
    let out_data = match kind {
        object::FileKind::Elf32 => copy_file::<elf::FileHeader32<Endianness>>(in_data).unwrap(),
        object::FileKind::Elf64 => copy_file::<elf::FileHeader64<Endianness>>(in_data).unwrap(),
        _ => {
            eprintln!("Not an ELF file");
            process::exit(1);
        }
    };
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}

struct Section {
    index: object::write::elf::SectionIndex,
    offset: usize,
    name: Option<object::write::StringId>,
}

struct Dynamic {
    tag: u64,
    val: u64,
    string: Option<object::write::StringId>,
}

struct Symbol {
    index: object::write::elf::SymbolIndex,
    name: Option<object::write::StringId>,
    section: Option<object::write::elf::SectionIndex>,
}

fn copy_file<Elf: FileHeader<Endian = Endianness>>(
    in_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let in_elf = Elf::parse(in_data)?;
    let endian = in_elf.endian()?;
    // TODO: write segments
    let in_segments = in_elf.program_headers(endian, in_data)?;
    let in_sections = in_elf.sections(endian, in_data)?;
    let in_syms = in_sections.symbols(endian, in_data, elf::SHT_SYMTAB)?;
    let in_dynsyms = in_sections.symbols(endian, in_data, elf::SHT_DYNSYM)?;

    let mut out_data = Vec::new();
    let mut writer = object::write::elf::Writer::new(endian, in_elf.is_class_64(), &mut out_data);
    writer.reserve_file_header();

    let mut out_sections = HashMap::new();
    for (i, in_section) in in_sections.iter().enumerate() {
        match in_section.sh_type(endian) {
            elf::SHT_PROGBITS | elf::SHT_NOBITS | elf::SHT_NOTE | elf::SHT_REL | elf::SHT_RELA => {
                let index = writer.reserve_section();
                let name = Some(writer.section_name(in_sections.section_name(endian, in_section)?));
                out_sections.insert(
                    i,
                    Section {
                        index,
                        offset: 0,
                        name,
                    },
                );
            }
            _ => {}
        }
    }

    let mut out_dyns = Vec::new();
    if let Some(dynamic) = in_segments
        .iter()
        .find(|x| x.p_type(endian) == elf::PT_DYNAMIC)
    {
        for d in dynamic.dynamic(endian, in_data)?.unwrap() {
            let tag = d.d_tag(endian).into();
            let val = d.d_val(endian).into();
            let string = if tag == elf::DT_NEEDED.into() {
                let s = in_dynsyms
                    .strings()
                    .get(val.try_into()?)
                    .map_err(|_| "invalid dynamic string")?;
                Some(writer.dynamic_string(s))
            } else {
                None
            };
            out_dyns.push(Dynamic { tag, val, string });
            if tag == elf::DT_NULL.into() {
                break;
            }
        }
    }

    let mut out_dynsyms = HashMap::new();
    for (i, in_dynsym) in in_dynsyms.iter().enumerate().skip(1) {
        let index = writer.reserve_dynamic_symbol();
        let name = if in_dynsym.st_name(endian) != 0 {
            Some(writer.dynamic_string(in_dynsyms.symbol_name(endian, in_dynsym)?))
        } else {
            None
        };
        out_dynsyms.insert(
            i,
            Symbol {
                index,
                name,
                section: None,
            },
        );
    }

    writer.reserve_dynsym();
    writer.reserve_dynstr();

    // TODO: sort sections by address before reserving data
    for (i, in_section) in in_sections.iter().enumerate() {
        match in_section.sh_type(endian) {
            elf::SHT_PROGBITS | elf::SHT_NOTE => {
                let out_section = out_sections.get_mut(&i).unwrap();
                out_section.offset = writer.reserve(
                    in_section.sh_size(endian).into() as usize,
                    in_section.sh_addralign(endian).into() as usize,
                );
            }
            _ => {}
        }
    }

    // TODO: this should be at end of alloc sections
    writer.reserve_dynamic(out_dyns.len());

    let mut num_local = 0;
    let mut out_syms = HashMap::new();
    for (i, in_sym) in in_syms.iter().enumerate().skip(1) {
        // Skip symbols for sections we aren't copying.
        let section = match in_syms.symbol_section(endian, in_sym, i) {
            Some(in_section) => match out_sections.get(&(in_section as usize)) {
                Some(out_section) => Some(out_section.index),
                None => continue,
            },
            None => None,
        };
        let index = writer.reserve_symbol(section);
        let name = if in_sym.st_name(endian) != 0 {
            Some(writer.string(in_syms.symbol_name(endian, in_sym)?))
        } else {
            None
        };
        out_syms.insert(
            i,
            Symbol {
                index,
                name,
                section,
            },
        );
        if in_sym.st_bind() == elf::STB_LOCAL {
            num_local = writer.symtab_num();
        }
    }
    writer.reserve_symtab();
    writer.reserve_symtab_shndx();

    for (i, in_section) in in_sections.iter().enumerate() {
        match in_section.sh_type(endian) {
            elf::SHT_REL => {
                let rels = in_section.rel(endian, in_data)?.unwrap();
                let out_section = out_sections.get_mut(&i).unwrap();
                out_section.offset = writer.reserve_relocations(rels.len(), false);
            }
            elf::SHT_RELA => {
                let rels = in_section.rela(endian, in_data)?.unwrap();
                let out_section = out_sections.get_mut(&i).unwrap();
                out_section.offset = writer.reserve_relocations(rels.len(), true);
            }
            _ => {}
        }
    }

    writer.reserve_strtab();
    writer.reserve_shstrtab();
    writer.reserve_section_headers();

    writer.write_file_header(object::write::elf::FileHeader {
        e_ident: elf::Ident {
            os_abi: in_elf.e_ident().os_abi,
            abi_version: in_elf.e_ident().abi_version,
            ..Default::default()
        },
        e_type: in_elf.e_type(endian),
        e_machine: in_elf.e_machine(endian),
        e_entry: in_elf.e_entry(endian).into(),
        e_flags: in_elf.e_flags(endian),
        ..Default::default()
    })?;

    writer.write_null_dynamic_symbol();
    for (i, in_dynsym) in in_dynsyms.iter().enumerate() {
        let out_dynsym = match out_dynsyms.get(&i) {
            Some(out_dynsym) => out_dynsym,
            None => continue,
        };
        writer.write_dynamic_symbol(
            out_dynsym.name,
            object::write::elf::Sym {
                st_name: 0,
                st_info: in_dynsym.st_info(),
                st_other: in_dynsym.st_other(),
                st_shndx: 0,
                st_value: in_dynsym.st_value(endian).into(),
                st_size: in_dynsym.st_size(endian).into(),
            },
        );
    }
    writer.write_dynstr();

    for (i, in_section) in in_sections.iter().enumerate() {
        match in_section.sh_type(endian) {
            elf::SHT_PROGBITS | elf::SHT_NOTE => {
                let out_section = &out_sections[&i];
                writer.write_align(in_section.sh_addralign(endian).into() as usize);
                debug_assert_eq!(out_section.offset, writer.len());
                writer.write(in_section.data(endian, in_data)?);
            }
            _ => {}
        }
    }

    if !out_dyns.is_empty() {
        writer.write_align_dynamic();
    }
    for out_dyn in out_dyns {
        if let Some(string) = out_dyn.string {
            writer.write_dynamic_string(out_dyn.tag, string);
        } else {
            writer.write_dynamic(out_dyn.tag, out_dyn.val);
        }
    }

    writer.write_null_symbol();
    for (i, in_sym) in in_syms.iter().enumerate() {
        let out_sym = match out_syms.get(&i) {
            Some(out_sym) => out_sym,
            None => continue,
        };
        writer.write_symbol(
            out_sym.name,
            out_sym.section,
            object::write::elf::Sym {
                st_name: 0,
                st_info: in_sym.st_info(),
                st_other: in_sym.st_other(),
                st_shndx: 0,
                st_value: in_sym.st_value(endian).into(),
                st_size: in_sym.st_size(endian).into(),
            },
        );
    }
    writer.write_symtab_shndx();

    let is_mips64el = in_elf.e_machine(endian) == elf::EM_MIPS
        && in_elf.is_class_64()
        && endian == Endianness::Little;
    for in_section in in_sections.iter() {
        let out_syms = if in_section.sh_link(endian) == in_syms.section() as u32 {
            &out_syms
        } else {
            &out_dynsyms
        };
        match in_section.sh_type(endian) {
            elf::SHT_REL => {
                let rels = in_section.rel(endian, in_data)?.unwrap();
                writer.write_align_relocation();
                for rel in rels {
                    let in_sym = rel.r_sym(endian);
                    let out_sym = if in_sym != 0 {
                        out_syms.get(&(in_sym as usize)).unwrap().index.0
                    } else {
                        0
                    };
                    writer.write_relocation(
                        is_mips64el,
                        false,
                        object::write::elf::Rel {
                            r_offset: rel.r_offset(endian).into(),
                            r_sym: out_sym,
                            r_type: rel.r_type(endian),
                            r_addend: 0,
                        },
                    );
                }
            }
            elf::SHT_RELA => {
                let rels = in_section.rela(endian, in_data)?.unwrap();
                writer.write_align_relocation();
                for rel in rels {
                    let in_sym = rel.r_sym(endian, is_mips64el);
                    let out_sym = if in_sym != 0 {
                        out_syms.get(&(in_sym as usize)).unwrap().index.0
                    } else {
                        0
                    };
                    writer.write_relocation(
                        is_mips64el,
                        true,
                        object::write::elf::Rel {
                            r_offset: rel.r_offset(endian).into(),
                            r_sym: out_sym,
                            r_type: rel.r_type(endian, is_mips64el),
                            r_addend: rel.r_addend(endian).into(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    writer.write_strtab();
    writer.write_shstrtab();

    writer.write_null_section_header();
    for (i, in_section) in in_sections.iter().enumerate() {
        if let Some(out_section) = out_sections.get(&i) {
            let mut sh_link = 0;
            let mut sh_info = 0;
            match in_section.sh_type(endian) {
                elf::SHT_REL | elf::SHT_RELA => {
                    if in_section.sh_link(endian) == in_syms.section() as u32 {
                        sh_link = writer.symtab_index().0;
                    } else if in_section.sh_link(endian) == in_dynsyms.section() as u32 {
                        sh_link = writer.dynsym_index().0;
                    }
                    if in_section.sh_info(endian) != 0 {
                        sh_info = out_sections[&(in_section.sh_info(endian) as usize)].index.0;
                    }
                }
                _ => {}
            }
            writer.write_section_header(
                out_section.name,
                object::write::elf::SectionHeader {
                    sh_name: 0,
                    sh_type: in_section.sh_type(endian),
                    sh_flags: in_section.sh_flags(endian).into(),
                    sh_addr: in_section.sh_addr(endian).into(),
                    sh_offset: out_section.offset as u64,
                    sh_size: in_section.sh_size(endian).into(),
                    sh_link,
                    sh_info,
                    sh_addralign: in_section.sh_addralign(endian).into(),
                    sh_entsize: in_section.sh_entsize(endian).into(),
                },
            );
        }
    }
    writer.write_dynsym_section_header(1);
    writer.write_dynstr_section_header();
    writer.write_dynamic_section_header();
    writer.write_symtab_section_header(num_local);
    writer.write_symtab_shndx_section_header();
    writer.write_strtab_section_header();
    writer.write_shstrtab_section_header();
    debug_assert_eq!(writer.reserved_len(), writer.len());

    Ok(out_data)
}
