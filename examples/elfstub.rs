use object::read::elf::{Dyn, FileHeader, Sym};
use object::Endianness;
use std::env;
use std::error::Error;
use std::fs::{self, File};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let file = File::open(&args[1])?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data_in = &*mmap;
    let elf_in = object::elf::FileHeader64::<Endianness>::parse(data_in)?;
    let endian = elf_in.endian()?;
    let sections_in = elf_in.sections(endian, data_in)?;
    let symbols_in = sections_in.symbols(endian, data_in, object::elf::SHT_DYNSYM)?;
    let versym_in = sections_in.gnu_versym(endian, data_in)?;
    let verdef_in = sections_in.gnu_verdef(endian, data_in)?;
    let mut verdef_count = 0;
    let mut verdaux_count = 0;

    let mut data_out = Vec::new();
    let mut elf_out = object::write::elf::Writer::new(endian, elf_in.is_class_64(), &mut data_out);

    // New dynamic symbol table, dropping undefined symbols.
    let mut symbols_out = vec![];
    let mut used = vec![];
    if !symbols_in.is_empty() {
        let mut stable_value = 0;
        // Drop symbols which are not defined by this library.
        for sym in symbols_in.iter() {
            if !sym.is_undefined(endian) {
                let name_in = symbols_in.symbol_name(endian, sym)?;
                let name_out = elf_out.add_dynamic_string(name_in);
                elf_out.reserve_dynamic_symbol_index();
                symbols_out.push(object::write::elf::Sym {
                    name: Some(name_out),
                    section: None,
                    st_info: sym.st_info(),
                    st_other: sym.st_other(),
                    // Fix it up to an arbitrary stable section value so the
                    // number and ordering of sections can never affect the
                    // content of the symbol table.
                    st_shndx: 1,
                    // Substitute non-zero addresses, dependent on size/layout of
                    // sections with a stable address determined by the index of
                    // this symbol table entry in the symbol table.
                    st_value: if sym.st_value.get(endian) == 0 {
                        0
                    } else {
                        stable_value += 1;
                        stable_value
                    },
                    // For functions, set the size to zero, to avoid leaking an
                    // address that is can change base on "implementation".
                    st_size: if sym.st_type() == object::elf::STT_FUNC {
                        0
                    } else {
                        sym.st_size(endian)
                    },
                });
                used.push(true);
            } else {
                used.push(false);
            }
        }

        elf_out.reserve_dynsym_section_index();
        if versym_in.is_some() {
            elf_out.reserve_gnu_versym_section_index();
        }
        if verdef_in.is_some() {
            elf_out.reserve_gnu_verdef_section_index();
        }
    }

    // To maintain consistent ordering with linkers, we put the dynstr section
    // *before* the dynamic section.
    elf_out.reserve_dynstr_section_index();

    // New dynamic section -- just SONAME.
    let mut dynamic_out = vec![];
    if let Some((dynamic, link)) = sections_in.dynamic(endian, data_in)? {
        let dynstr_in = sections_in.strings(endian, data_in, link)?;
        // We only keep SONAME.  Everything else -- like DT_NEEDED tags -- are
        // dropped (as they can leak implementation details).
        for d in dynamic {
            if d.d_tag(endian) == object::elf::DT_SONAME.into() {
                dynamic_out.push((
                    object::elf::DT_SONAME,
                    0,
                    Some(
                        elf_out.add_dynamic_string(dynstr_in.get(d.d_val(endian) as u32).unwrap()),
                    ),
                ));
                break;
            }
        }

        // Always end with the DT_NULL entry.
        dynamic_out.push((object::elf::DT_NULL, 0, None));

        elf_out.reserve_dynamic_section_index();
    }

    elf_out.reserve_shstrtab_section_index();

    elf_out.reserve_file_header();
    if !symbols_out.is_empty() {
        elf_out.reserve_dynsym();
        if versym_in.is_some() {
            elf_out.reserve_gnu_versym();
        }
        if let Some((mut verdefs, link)) = verdef_in.clone() {
            // Add version strings to dynstr section
            let strings = sections_in.strings(endian, data_in, link)?;
            while let Some((_, mut verdauxs)) = verdefs.next()? {
                verdef_count += 1;
                while let Some(verdaux) = verdauxs.next()? {
                    elf_out.add_dynamic_string(verdaux.name(endian, strings)?);
                    verdaux_count += 1;
                }
            }
            elf_out.reserve_gnu_verdef(verdef_count, verdaux_count);
        }
    }
    elf_out.reserve_dynstr();
    if !dynamic_out.is_empty() {
        elf_out.reserve_dynamic(dynamic_out.len());
    }
    elf_out.reserve_shstrtab();
    elf_out.reserve_section_headers();

    elf_out.write_file_header(&object::write::elf::FileHeader {
        os_abi: elf_in.e_ident().os_abi,
        abi_version: elf_in.e_ident().abi_version,
        e_type: elf_in.e_type(endian),
        e_machine: elf_in.e_machine(endian),
        e_entry: 0,
        e_flags: elf_in.e_flags(endian),
    })?;

    if !symbols_out.is_empty() {
        // Write out new dynsym table.
        elf_out.write_null_dynamic_symbol();
        for sym in &symbols_out {
            elf_out.write_dynamic_symbol(sym);
        }

        // If present, also update `.gnu.version`, by removing corresponding
        // slots also removed above.
        if let Some((versym_in, _link)) = versym_in {
            assert_eq!(versym_in.len(), used.len());
            elf_out.write_null_gnu_versym();
            for (idx, versym) in versym_in.iter().enumerate() {
                if used[idx] {
                    elf_out.write_gnu_versym(versym.0.get(endian));
                }
            }
        }

        // If present, also update `.gnu.version_d`, with new string offsets.
        if let Some((mut verdefs, link)) = verdef_in.clone() {
            let strings = sections_in.strings(endian, data_in, link)?;
            elf_out.write_align_gnu_verdef();
            while let Some((verdef, mut verdauxs)) = verdefs.next()? {
                let verdaux = verdauxs.next()?.unwrap();
                elf_out.write_gnu_verdef(&object::write::elf::Verdef {
                    version: verdef.vd_version.get(endian),
                    flags: verdef.vd_flags.get(endian),
                    index: verdef.vd_ndx.get(endian),
                    aux_count: verdef.vd_cnt.get(endian),
                    name: elf_out.get_dynamic_string(verdaux.name(endian, strings)?),
                });
                while let Some(verdaux) = verdauxs.next()? {
                    elf_out.write_gnu_verdaux(
                        elf_out.get_dynamic_string(verdaux.name(endian, strings)?),
                    );
                }
            }
        }
    }

    // Write dynamic string table.
    elf_out.write_dynstr();

    if !dynamic_out.is_empty() {
        // Write out new dynamic sestion.
        elf_out.write_align_dynamic();
        for (tag, val, string) in dynamic_out {
            if let Some(string) = string {
                elf_out.write_dynamic_string(tag, string);
            } else {
                elf_out.write_dynamic(tag, val);
            }
        }
    }

    elf_out.write_shstrtab();

    elf_out.write_null_section_header();
    elf_out.write_dynsym_section_header(0, 1);
    elf_out.write_gnu_versym_section_header(0);
    elf_out.write_gnu_verdef_section_header(0);
    elf_out.write_dynstr_section_header(0);
    elf_out.write_dynamic_section_header(0);
    elf_out.write_shstrtab_section_header();

    fs::write(&args[2], data_out)?;
    Ok(())
}
