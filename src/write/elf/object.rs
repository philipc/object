use std::vec::Vec;

use crate::elf;
use crate::endian::*;
use crate::pod::bytes_of;
use crate::write::elf::writer::*;
use crate::write::string::StringId;
use crate::write::*;
use crate::AddressSize;

#[derive(Default, Clone, Copy)]
struct ComdatOffsets {
    offset: usize,
    str_id: Option<StringId>,
    len: usize,
}

#[derive(Default, Clone, Copy)]
struct SectionOffsets {
    index: SectionIndex,
    offset: usize,
    str_id: Option<StringId>,
    reloc_index: SectionIndex,
    reloc_offset: usize,
    reloc_str_id: Option<StringId>,
}

#[derive(Default, Clone, Copy)]
struct SymbolOffsets {
    index: SymbolIndex,
    str_id: Option<StringId>,
}

impl Object {
    pub(crate) fn elf_section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind) {
        match section {
            StandardSection::Text => (&[], &b".text"[..], SectionKind::Text),
            StandardSection::Data => (&[], &b".data"[..], SectionKind::Data),
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyString => {
                (&[], &b".rodata"[..], SectionKind::ReadOnlyData)
            }
            StandardSection::ReadOnlyDataWithRel => (&[], b".data.rel.ro", SectionKind::Data),
            StandardSection::UninitializedData => {
                (&[], &b".bss"[..], SectionKind::UninitializedData)
            }
            StandardSection::Tls => (&[], &b".tdata"[..], SectionKind::Tls),
            StandardSection::UninitializedTls => {
                (&[], &b".tbss"[..], SectionKind::UninitializedTls)
            }
            StandardSection::TlsVariables => {
                // Unsupported section.
                (&[], &[], SectionKind::TlsVariables)
            }
            StandardSection::Common => {
                // Unsupported section.
                (&[], &[], SectionKind::Common)
            }
        }
    }

    pub(crate) fn elf_subsection_name(&self, section: &[u8], value: &[u8]) -> Vec<u8> {
        let mut name = section.to_vec();
        name.push(b'.');
        name.extend_from_slice(value);
        name
    }

    fn elf_has_relocation_addend(&self) -> Result<bool> {
        Ok(match self.architecture {
            Architecture::Aarch64 => true,
            Architecture::Arm => false,
            Architecture::Avr => true,
            Architecture::Bpf => false,
            Architecture::I386 => false,
            Architecture::X86_64 => true,
            Architecture::X86_64_X32 => true,
            Architecture::Hexagon => true,
            Architecture::Mips => false,
            Architecture::Mips64 => true,
            Architecture::Msp430 => true,
            Architecture::PowerPc => true,
            Architecture::PowerPc64 => true,
            Architecture::Riscv64 => true,
            Architecture::Riscv32 => true,
            Architecture::S390x => true,
            Architecture::Sparc64 => true,
            _ => {
                return Err(Error(format!(
                    "unimplemented architecture {:?}",
                    self.architecture
                )));
            }
        })
    }

    pub(crate) fn elf_fixup_relocation(&mut self, mut relocation: &mut Relocation) -> Result<i64> {
        // Return true if we should use a section symbol to avoid preemption.
        fn want_section_symbol(relocation: &Relocation, symbol: &Symbol) -> bool {
            if symbol.scope != SymbolScope::Dynamic {
                // Only dynamic symbols can be preemptible.
                return false;
            }
            match symbol.kind {
                SymbolKind::Text | SymbolKind::Data => {}
                _ => return false,
            }
            match relocation.kind {
                // Anything using GOT or PLT is preemptible.
                // We also require that `Other` relocations must already be correct.
                RelocationKind::Got
                | RelocationKind::GotRelative
                | RelocationKind::GotBaseRelative
                | RelocationKind::PltRelative
                | RelocationKind::Elf(_) => return false,
                // Absolute relocations are preemptible for non-local data.
                // TODO: not sure if this rule is exactly correct
                // This rule was added to handle global data references in debuginfo.
                // Maybe this should be a new relocation kind so that the caller can decide.
                RelocationKind::Absolute => {
                    if symbol.kind == SymbolKind::Data {
                        return false;
                    }
                }
                _ => {}
            }
            true
        }

        // Use section symbols for relocations where required to avoid preemption.
        // Otherwise, the linker will fail with:
        //     relocation R_X86_64_PC32 against symbol `SomeSymbolName' can not be used when
        //     making a shared object; recompile with -fPIC
        let symbol = &self.symbols[relocation.symbol.0];
        if want_section_symbol(relocation, symbol) {
            if let Some(section) = symbol.section.id() {
                relocation.addend += symbol.value as i64;
                relocation.symbol = self.section_symbol(section);
            }
        }

        // Determine whether the addend is stored in the relocation or the data.
        if self.elf_has_relocation_addend()? {
            Ok(0)
        } else {
            let constant = relocation.addend;
            relocation.addend = 0;
            Ok(constant)
        }
    }

    pub(crate) fn elf_write(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        // Create reloc section header names so we can reference them.
        let is_rela = self.elf_has_relocation_addend()?;
        let reloc_names: Vec<_> = self
            .sections
            .iter()
            .map(|section| {
                let mut reloc_name = Vec::new();
                if !section.relocations.is_empty() {
                    reloc_name.extend_from_slice(if is_rela {
                        &b".rela"[..]
                    } else {
                        &b".rel"[..]
                    });
                    reloc_name.extend_from_slice(&section.name);
                }
                reloc_name
            })
            .collect();

        // Calculate offsets of everything.
        let is_64 = match self.architecture.address_size().unwrap() {
            AddressSize::U8 | AddressSize::U16 | AddressSize::U32 => false,
            AddressSize::U64 => true,
        };
        let mut writer = Writer::new(self.endian, is_64, buffer);
        writer.reserve_file_header();

        // Calculate size of section data.
        let mut comdat_offsets = vec![ComdatOffsets::default(); self.comdats.len()];
        for (index, comdat) in self.comdats.iter().enumerate() {
            if comdat.kind != ComdatKind::Any {
                return Err(Error(format!(
                    "unsupported COMDAT symbol `{}` kind {:?}",
                    self.symbols[comdat.symbol.0].name().unwrap_or(""),
                    comdat.kind
                )));
            }

            comdat_offsets[index].str_id = Some(writer.section_name(b".group"));
            writer.reserve_section();
            let len = (comdat.sections.len() + 1) * 4;
            comdat_offsets[index].len = len;
            comdat_offsets[index].offset = writer.reserve(len, 4);
        }
        let mut section_offsets = vec![SectionOffsets::default(); self.sections.len()];
        for (index, section) in self.sections.iter().enumerate() {
            section_offsets[index].str_id = Some(writer.section_name(&section.name));
            section_offsets[index].index = writer.reserve_section();
            section_offsets[index].offset =
                writer.reserve(section.data.len(), section.align as usize);
            if !section.relocations.is_empty() {
                section_offsets[index].reloc_str_id =
                    Some(writer.section_name(&reloc_names[index]));
                section_offsets[index].reloc_index = writer.reserve_section();
            }
        }

        // Calculate index of symbols and add symbol strings to strtab.
        let mut symbol_offsets = vec![SymbolOffsets::default(); self.symbols.len()];
        // Local symbols must come before global.
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.is_local() {
                let section_index = symbol.section.id().map(|s| section_offsets[s.0].index);
                symbol_offsets[index].index = writer.reserve_symbol(section_index);
            }
        }
        let symtab_num_local = writer.symtab_num();
        for (index, symbol) in self.symbols.iter().enumerate() {
            if !symbol.is_local() {
                let section_index = symbol.section.id().map(|s| section_offsets[s.0].index);
                symbol_offsets[index].index = writer.reserve_symbol(section_index);
            }
        }
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.kind != SymbolKind::Section && !symbol.name.is_empty() {
                symbol_offsets[index].str_id = Some(writer.string(&symbol.name));
            }
        }

        // Calculate size of relocations.
        for (index, section) in self.sections.iter().enumerate() {
            let count = section.relocations.len();
            if count != 0 {
                section_offsets[index].reloc_offset = writer.reserve_relocations(count, is_rela);
            }
        }

        // Calculate size of synthetic sections.
        writer.reserve_symtab();
        writer.reserve_symtab_shndx();
        writer.reserve_strtab();
        writer.reserve_shstrtab();

        // Calculate size of section headers.
        writer.reserve_section_headers();

        // Start writing.
        let e_type = elf::ET_REL;
        let e_machine = match self.architecture {
            Architecture::Aarch64 => elf::EM_AARCH64,
            Architecture::Arm => elf::EM_ARM,
            Architecture::Avr => elf::EM_AVR,
            Architecture::Bpf => elf::EM_BPF,
            Architecture::I386 => elf::EM_386,
            Architecture::X86_64 => elf::EM_X86_64,
            Architecture::X86_64_X32 => elf::EM_X86_64,
            Architecture::Hexagon => elf::EM_HEXAGON,
            Architecture::Mips => elf::EM_MIPS,
            Architecture::Mips64 => elf::EM_MIPS,
            Architecture::Msp430 => elf::EM_MSP430,
            Architecture::PowerPc => elf::EM_PPC,
            Architecture::PowerPc64 => elf::EM_PPC64,
            Architecture::Riscv32 => elf::EM_RISCV,
            Architecture::Riscv64 => elf::EM_RISCV,
            Architecture::S390x => elf::EM_S390,
            Architecture::Sparc64 => elf::EM_SPARCV9,
            _ => {
                return Err(Error(format!(
                    "unimplemented architecture {:?}",
                    self.architecture
                )));
            }
        };
        let e_flags = if let FileFlags::Elf { e_flags } = self.flags {
            e_flags
        } else {
            0
        };
        writer.write_file_header(FileHeader {
            e_type,
            e_machine,
            e_flags,
            ..Default::default()
        })?;

        // Write section data.
        for (index, comdat) in self.comdats.iter().enumerate() {
            let mut data = Vec::new();
            data.extend_from_slice(bytes_of(&U32::new(self.endian, elf::GRP_COMDAT)));
            for section in &comdat.sections {
                data.extend_from_slice(bytes_of(&U32::new(
                    self.endian,
                    section_offsets[section.0].index.0,
                )));
            }

            writer.write_align(4);
            debug_assert_eq!(comdat_offsets[index].offset, writer.len());
            debug_assert_eq!(comdat_offsets[index].len, data.len());
            writer.write(data.as_slice());
        }
        for (index, section) in self.sections.iter().enumerate() {
            let len = section.data.len();
            if len != 0 {
                writer.write_align(section.align as usize);
                debug_assert_eq!(section_offsets[index].offset, writer.len());
                writer.write(section.data.as_slice());
            }
        }

        // Write relocations.
        let is_mips64el =
            self.architecture == Architecture::Mips64 && self.endian == Endianness::Little;
        for (index, section) in self.sections.iter().enumerate() {
            if !section.relocations.is_empty() {
                writer.write_align_relocation();
                debug_assert_eq!(section_offsets[index].reloc_offset, writer.len());
                for reloc in &section.relocations {
                    let r_type = match self.architecture {
                        Architecture::Aarch64 => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => {
                                elf::R_AARCH64_ABS64
                            }
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => {
                                elf::R_AARCH64_ABS32
                            }
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 16) => {
                                elf::R_AARCH64_ABS16
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 64) => {
                                elf::R_AARCH64_PREL64
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => {
                                elf::R_AARCH64_PREL32
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 16) => {
                                elf::R_AARCH64_PREL16
                            }
                            (RelocationKind::Relative, RelocationEncoding::AArch64Call, 26)
                            | (RelocationKind::PltRelative, RelocationEncoding::AArch64Call, 26) => {
                                elf::R_AARCH64_CALL26
                            }
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Arm => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_ARM_ABS32,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Avr => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_AVR_32,
                            (RelocationKind::Absolute, _, 16) => elf::R_AVR_16,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Bpf => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 64) => elf::R_BPF_64_64,
                            (RelocationKind::Absolute, _, 32) => elf::R_BPF_64_32,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::I386 => match (reloc.kind, reloc.size) {
                            (RelocationKind::Absolute, 32) => elf::R_386_32,
                            (RelocationKind::Relative, 32) => elf::R_386_PC32,
                            (RelocationKind::Got, 32) => elf::R_386_GOT32,
                            (RelocationKind::PltRelative, 32) => elf::R_386_PLT32,
                            (RelocationKind::GotBaseOffset, 32) => elf::R_386_GOTOFF,
                            (RelocationKind::GotBaseRelative, 32) => elf::R_386_GOTPC,
                            (RelocationKind::Absolute, 16) => elf::R_386_16,
                            (RelocationKind::Relative, 16) => elf::R_386_PC16,
                            (RelocationKind::Absolute, 8) => elf::R_386_8,
                            (RelocationKind::Relative, 8) => elf::R_386_PC8,
                            (RelocationKind::Elf(x), _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::X86_64 | Architecture::X86_64_X32 => {
                            match (reloc.kind, reloc.encoding, reloc.size) {
                                (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => {
                                    elf::R_X86_64_64
                                }
                                (RelocationKind::Relative, _, 32) => elf::R_X86_64_PC32,
                                (RelocationKind::Got, _, 32) => elf::R_X86_64_GOT32,
                                (RelocationKind::PltRelative, _, 32) => elf::R_X86_64_PLT32,
                                (RelocationKind::GotRelative, _, 32) => elf::R_X86_64_GOTPCREL,
                                (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => {
                                    elf::R_X86_64_32
                                }
                                (RelocationKind::Absolute, RelocationEncoding::X86Signed, 32) => {
                                    elf::R_X86_64_32S
                                }
                                (RelocationKind::Absolute, _, 16) => elf::R_X86_64_16,
                                (RelocationKind::Relative, _, 16) => elf::R_X86_64_PC16,
                                (RelocationKind::Absolute, _, 8) => elf::R_X86_64_8,
                                (RelocationKind::Relative, _, 8) => elf::R_X86_64_PC8,
                                (RelocationKind::Elf(x), _, _) => x,
                                _ => {
                                    return Err(Error(format!(
                                        "unimplemented relocation {:?}",
                                        reloc
                                    )));
                                }
                            }
                        }
                        Architecture::Hexagon => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_HEX_32,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Mips | Architecture::Mips64 => {
                            match (reloc.kind, reloc.encoding, reloc.size) {
                                (RelocationKind::Absolute, _, 16) => elf::R_MIPS_16,
                                (RelocationKind::Absolute, _, 32) => elf::R_MIPS_32,
                                (RelocationKind::Absolute, _, 64) => elf::R_MIPS_64,
                                (RelocationKind::Elf(x), _, _) => x,
                                _ => {
                                    return Err(Error(format!(
                                        "unimplemented relocation {:?}",
                                        reloc
                                    )));
                                }
                            }
                        }
                        Architecture::Msp430 => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_MSP430_32,
                            (RelocationKind::Absolute, _, 16) => elf::R_MSP430_16_BYTE,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::PowerPc => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_PPC_ADDR32,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::PowerPc64 => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, _, 32) => elf::R_PPC64_ADDR32,
                            (RelocationKind::Absolute, _, 64) => elf::R_PPC64_ADDR64,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Riscv32 | Architecture::Riscv64 => {
                            match (reloc.kind, reloc.encoding, reloc.size) {
                                (RelocationKind::Absolute, _, 32) => elf::R_RISCV_32,
                                (RelocationKind::Absolute, _, 64) => elf::R_RISCV_64,
                                (RelocationKind::Elf(x), _, _) => x,
                                _ => {
                                    return Err(Error(format!(
                                        "unimplemented relocation {:?}",
                                        reloc
                                    )));
                                }
                            }
                        }
                        Architecture::S390x => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 8) => {
                                elf::R_390_8
                            }
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 16) => {
                                elf::R_390_16
                            }
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => {
                                elf::R_390_32
                            }
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => {
                                elf::R_390_64
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 16) => {
                                elf::R_390_PC16
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => {
                                elf::R_390_PC32
                            }
                            (RelocationKind::Relative, RelocationEncoding::Generic, 64) => {
                                elf::R_390_PC64
                            }
                            (RelocationKind::Relative, RelocationEncoding::S390xDbl, 16) => {
                                elf::R_390_PC16DBL
                            }
                            (RelocationKind::Relative, RelocationEncoding::S390xDbl, 32) => {
                                elf::R_390_PC32DBL
                            }
                            (RelocationKind::PltRelative, RelocationEncoding::S390xDbl, 16) => {
                                elf::R_390_PLT16DBL
                            }
                            (RelocationKind::PltRelative, RelocationEncoding::S390xDbl, 32) => {
                                elf::R_390_PLT32DBL
                            }
                            (RelocationKind::Got, RelocationEncoding::Generic, 16) => {
                                elf::R_390_GOT16
                            }
                            (RelocationKind::Got, RelocationEncoding::Generic, 32) => {
                                elf::R_390_GOT32
                            }
                            (RelocationKind::Got, RelocationEncoding::Generic, 64) => {
                                elf::R_390_GOT64
                            }
                            (RelocationKind::GotRelative, RelocationEncoding::S390xDbl, 32) => {
                                elf::R_390_GOTENT
                            }
                            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 16) => {
                                elf::R_390_GOTOFF16
                            }
                            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 32) => {
                                elf::R_390_GOTOFF32
                            }
                            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 64) => {
                                elf::R_390_GOTOFF64
                            }
                            (RelocationKind::GotBaseRelative, RelocationEncoding::Generic, 64) => {
                                elf::R_390_GOTPC
                            }
                            (RelocationKind::GotBaseRelative, RelocationEncoding::S390xDbl, 32) => {
                                elf::R_390_GOTPCDBL
                            }
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        Architecture::Sparc64 => match (reloc.kind, reloc.encoding, reloc.size) {
                            // TODO: use R_SPARC_32/R_SPARC_64 if aligned.
                            (RelocationKind::Absolute, _, 32) => elf::R_SPARC_UA32,
                            (RelocationKind::Absolute, _, 64) => elf::R_SPARC_UA64,
                            (RelocationKind::Elf(x), _, _) => x,
                            _ => {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        },
                        _ => {
                            if let RelocationKind::Elf(x) = reloc.kind {
                                x
                            } else {
                                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                            }
                        }
                    };
                    let r_sym = symbol_offsets[reloc.symbol.0].index.0;
                    writer.write_relocation(
                        is_mips64el,
                        is_rela,
                        Rel {
                            r_offset: reloc.offset,
                            r_sym,
                            r_type,
                            r_addend: reloc.addend,
                        },
                    );
                }
            }
        }

        // Write symbols.
        writer.write_null_symbol();
        let mut write_symbol = |index: usize, symbol: &Symbol| -> Result<()> {
            let st_info = if let SymbolFlags::Elf { st_info, .. } = symbol.flags {
                st_info
            } else {
                let st_type = match symbol.kind {
                    SymbolKind::Null => elf::STT_NOTYPE,
                    SymbolKind::Text => {
                        if symbol.is_undefined() {
                            elf::STT_NOTYPE
                        } else {
                            elf::STT_FUNC
                        }
                    }
                    SymbolKind::Data => {
                        if symbol.is_undefined() {
                            elf::STT_NOTYPE
                        } else if symbol.is_common() {
                            elf::STT_COMMON
                        } else {
                            elf::STT_OBJECT
                        }
                    }
                    SymbolKind::Section => elf::STT_SECTION,
                    SymbolKind::File => elf::STT_FILE,
                    SymbolKind::Tls => elf::STT_TLS,
                    SymbolKind::Label => elf::STT_NOTYPE,
                    SymbolKind::Unknown => {
                        if symbol.is_undefined() {
                            elf::STT_NOTYPE
                        } else {
                            return Err(Error(format!(
                                "unimplemented symbol `{}` kind {:?}",
                                symbol.name().unwrap_or(""),
                                symbol.kind
                            )));
                        }
                    }
                };
                let st_bind = if symbol.weak {
                    elf::STB_WEAK
                } else if symbol.is_undefined() {
                    elf::STB_GLOBAL
                } else if symbol.is_local() {
                    elf::STB_LOCAL
                } else {
                    elf::STB_GLOBAL
                };
                (st_bind << 4) + st_type
            };
            let st_other = if let SymbolFlags::Elf { st_other, .. } = symbol.flags {
                st_other
            } else if symbol.scope == SymbolScope::Linkage {
                elf::STV_HIDDEN
            } else {
                elf::STV_DEFAULT
            };
            let (st_shndx, section) = match symbol.section {
                SymbolSection::None => {
                    debug_assert_eq!(symbol.kind, SymbolKind::File);
                    (elf::SHN_ABS, None)
                }
                SymbolSection::Undefined => (elf::SHN_UNDEF, None),
                SymbolSection::Absolute => (elf::SHN_ABS, None),
                SymbolSection::Common => (elf::SHN_COMMON, None),
                SymbolSection::Section(id) => (0, Some(section_offsets[id.0].index)),
            };
            writer.write_symbol(
                symbol_offsets[index].str_id,
                section,
                Sym {
                    st_name: 0,
                    st_info,
                    st_other,
                    st_shndx,
                    st_value: symbol.value,
                    st_size: symbol.size,
                },
            );
            Ok(())
        };
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.is_local() {
                write_symbol(index, symbol)?;
            }
        }
        for (index, symbol) in self.symbols.iter().enumerate() {
            if !symbol.is_local() {
                write_symbol(index, symbol)?;
            }
        }
        writer.write_symtab_shndx();

        writer.write_strtab();
        writer.write_shstrtab();

        // Write section headers.
        writer.write_null_section_header();

        let symtab_index = writer.symtab_index();
        for (index, comdat) in self.comdats.iter().enumerate() {
            writer.write_section_header(
                comdat_offsets[index].str_id,
                SectionHeader {
                    sh_name: 0,
                    sh_type: elf::SHT_GROUP,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: comdat_offsets[index].offset as u64,
                    sh_size: comdat_offsets[index].len as u64,
                    sh_link: symtab_index.0,
                    sh_info: symbol_offsets[comdat.symbol.0].index.0,
                    sh_addralign: 4,
                    sh_entsize: 4,
                },
            );
        }
        for (index, section) in self.sections.iter().enumerate() {
            let sh_type = match section.kind {
                SectionKind::UninitializedData | SectionKind::UninitializedTls => elf::SHT_NOBITS,
                SectionKind::Note => elf::SHT_NOTE,
                SectionKind::Elf(sh_type) => sh_type,
                _ => elf::SHT_PROGBITS,
            };
            let sh_flags = if let SectionFlags::Elf { sh_flags } = section.flags {
                sh_flags
            } else {
                match section.kind {
                    SectionKind::Text => elf::SHF_ALLOC | elf::SHF_EXECINSTR,
                    SectionKind::Data => elf::SHF_ALLOC | elf::SHF_WRITE,
                    SectionKind::Tls => elf::SHF_ALLOC | elf::SHF_WRITE | elf::SHF_TLS,
                    SectionKind::UninitializedData => elf::SHF_ALLOC | elf::SHF_WRITE,
                    SectionKind::UninitializedTls => elf::SHF_ALLOC | elf::SHF_WRITE | elf::SHF_TLS,
                    SectionKind::ReadOnlyData => elf::SHF_ALLOC,
                    SectionKind::ReadOnlyString => {
                        elf::SHF_ALLOC | elf::SHF_STRINGS | elf::SHF_MERGE
                    }
                    SectionKind::OtherString => elf::SHF_STRINGS | elf::SHF_MERGE,
                    SectionKind::Other
                    | SectionKind::Debug
                    | SectionKind::Metadata
                    | SectionKind::Linker
                    | SectionKind::Note
                    | SectionKind::Elf(_) => 0,
                    SectionKind::Unknown | SectionKind::Common | SectionKind::TlsVariables => {
                        return Err(Error(format!(
                            "unimplemented section `{}` kind {:?}",
                            section.name().unwrap_or(""),
                            section.kind
                        )));
                    }
                }
                .into()
            };
            // TODO: not sure if this is correct, maybe user should determine this
            let sh_entsize = match section.kind {
                SectionKind::ReadOnlyString | SectionKind::OtherString => 1,
                _ => 0,
            };
            writer.write_section_header(
                section_offsets[index].str_id,
                SectionHeader {
                    sh_name: 0,
                    sh_type,
                    sh_flags,
                    sh_addr: 0,
                    sh_offset: section_offsets[index].offset as u64,
                    sh_size: section.size,
                    sh_link: 0,
                    sh_info: 0,
                    sh_addralign: section.align,
                    sh_entsize,
                },
            );

            if !section.relocations.is_empty() {
                writer.write_relocation_section_header(
                    section_offsets[index].reloc_str_id.unwrap(),
                    section_offsets[index].index,
                    section_offsets[index].reloc_offset,
                    section.relocations.len(),
                    is_rela,
                );
            }
        }

        writer.write_symtab_section_header(symtab_num_local);
        writer.write_symtab_shndx_section_header();

        writer.write_strtab_section_header();
        writer.write_shstrtab_section_header();

        debug_assert_eq!(writer.reserved_len(), writer.len());

        Ok(())
    }
}
