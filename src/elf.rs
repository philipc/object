use std::fmt;
use std::slice;
use alloc::vec::Vec;

use goblin::{elf, strtab};

use {DebugFileInfo, Machine, Object, ObjectSection, ObjectSegment, SectionKind, Symbol, SymbolKind,
     SymbolMap};

/// An ELF object file.
#[derive(Debug)]
pub struct ElfFile<'data> {
    elf: elf::Elf<'data>,
    data: &'data [u8],
}

/// An iterator over the segments of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    iter: slice::Iter<'file, elf::ProgramHeader>,
}

/// A segment of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegment<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    segment: &'file elf::ProgramHeader,
}

/// An iterator over the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    iter: slice::Iter<'file, elf::SectionHeader>,
}

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    section: &'file elf::SectionHeader,
}

/// An iterator over the symbols of an `ElfFile`.
pub struct ElfSymbolIterator<'data, 'file>
where
    'data: 'file,
{
    strtab: &'file strtab::Strtab<'data>,
    symbols: elf::sym::SymIterator<'data>,
    section_kinds: Vec<SectionKind>,
}

impl<'data> ElfFile<'data> {
    /// Get the ELF headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn elf(&self) -> &elf::Elf<'data> {
        &self.elf
    }

    /// Parse the raw ELF file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let elf = elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
        Ok(ElfFile { elf, data })
    }
}

impl<'data, 'file> Object<'data, 'file> for ElfFile<'data>
where
    'data: 'file,
{
    type Segment = ElfSegment<'data, 'file>;
    type SegmentIterator = ElfSegmentIterator<'data, 'file>;
    type Section = ElfSection<'data, 'file>;
    type SectionIterator = ElfSectionIterator<'data, 'file>;
    type SymbolIterator = ElfSymbolIterator<'data, 'file>;

    fn machine(&self) -> Machine {
        match self.elf.header.e_machine {
            elf::header::EM_ARM => Machine::Arm,
            elf::header::EM_AARCH64 => Machine::Arm64,
            elf::header::EM_386 => Machine::X86,
            elf::header::EM_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'file self) -> ElfSegmentIterator<'data, 'file> {
        ElfSegmentIterator {
            file: self,
            iter: self.elf.program_headers.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]> {
        for header in &self.elf.section_headers {
            if let Some(Ok(name)) = self.elf.shdr_strtab.get(header.sh_name) {
                if name == section_name {
                    return Some(&self.data[header.sh_offset as usize..][..header.sh_size as usize]);
                }
            }
        }
        None
    }

    fn sections(&'file self) -> ElfSectionIterator<'data, 'file> {
        ElfSectionIterator {
            file: self,
            iter: self.elf.section_headers.iter(),
        }
    }

    fn symbols(&'file self) -> ElfSymbolIterator<'data, 'file> {
        ElfSymbolIterator {
            strtab: &self.elf.strtab,
            symbols: self.elf.syms.iter(),
            section_kinds: self.sections().map(|x| x.kind()).collect(),
        }
    }

    fn dynamic_symbols(&'file self) -> ElfSymbolIterator<'data, 'file> {
        ElfSymbolIterator {
            strtab: &self.elf.dynstrtab,
            symbols: self.elf.dynsyms.iter(),
            section_kinds: self.sections().map(|x| x.kind()).collect(),
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut symbols: Vec<_> = self.symbols().filter(SymbolMap::filter).collect();
        symbols.sort_by_key(|x| x.address);
        SymbolMap { symbols, object_files: Vec::new() }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.elf.little_endian
    }

    fn has_debug_symbols(&self) -> bool {
        self.section_data_by_name(".debug_info").is_some()
    }

    fn debug_file_info(&self) -> Option<DebugFileInfo> { None }

    fn entry(&self) -> u64 {
        self.elf.entry
    }
}

impl<'data, 'file> Iterator for ElfSegmentIterator<'data, 'file> {
    type Item = ElfSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(segment) = self.iter.next() {
            if segment.p_type == elf::program_header::PT_LOAD {
                return Some(ElfSegment {
                    file: self.file,
                    segment,
                });
            }
        }
        None
    }
}

impl<'data, 'file> ObjectSegment<'data> for ElfSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.p_vaddr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.p_memsz
    }

    fn data(&self) -> &'data [u8] {
        &self.file.data[self.segment.p_offset as usize..][..self.segment.p_filesz as usize]
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        None
    }
}

impl<'data, 'file> Iterator for ElfSectionIterator<'data, 'file> {
    type Item = ElfSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            ElfSection {
                file: self.file,
                section,
            }
        })
    }
}

impl<'data, 'file> ObjectSection<'data> for ElfSection<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        self.section.sh_addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.sh_size
    }

    fn data(&self) -> &'data [u8] {
        if self.section.sh_type == elf::section_header::SHT_NOBITS {
            &[]
        } else {
            &self.file.data[self.section.sh_offset as usize..][..self.section.sh_size as usize]
        }
    }

    fn name(&self) -> Option<&str> {
        self.file
            .elf
            .shdr_strtab
            .get(self.section.sh_name)
            .and_then(Result::ok)
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    fn kind(&self) -> SectionKind {
        match self.section.sh_type {
            elf::section_header::SHT_PROGBITS => {
                if self.section.sh_flags & u64::from(elf::section_header::SHF_ALLOC) == 0 {
                    SectionKind::Unknown
                } else if self.section.sh_flags & u64::from(elf::section_header::SHF_EXECINSTR) != 0
                {
                    SectionKind::Text
                } else if self.section.sh_flags & u64::from(elf::section_header::SHF_WRITE) != 0 {
                    SectionKind::Data
                } else {
                    SectionKind::ReadOnlyData
                }
            }
            elf::section_header::SHT_NOBITS => SectionKind::UninitializedData,
            _ => SectionKind::Unknown,
        }
    }
}

impl<'data, 'file> fmt::Debug for ElfSymbolIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElfSymbolIterator").finish()
    }
}

impl<'data, 'file> Iterator for ElfSymbolIterator<'data, 'file> {
    type Item = Symbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.symbols.next().map(|symbol| {
            let name = self.strtab.get(symbol.st_name).and_then(Result::ok);
            let kind = match elf::sym::st_type(symbol.st_info) {
                elf::sym::STT_OBJECT => SymbolKind::Data,
                elf::sym::STT_FUNC => SymbolKind::Text,
                elf::sym::STT_SECTION => SymbolKind::Section,
                elf::sym::STT_FILE => SymbolKind::File,
                elf::sym::STT_COMMON => SymbolKind::Common,
                elf::sym::STT_TLS => SymbolKind::Tls,
                _ => SymbolKind::Unknown,
            };
            let section_kind = if symbol.st_shndx == elf::section_header::SHN_UNDEF as usize {
                None
            } else {
                self.section_kinds.get(symbol.st_shndx).cloned()
            };
            Symbol {
                name,
                address: symbol.st_value,
                size: symbol.st_size,
                kind,
                section_kind,
                global: elf::sym::st_bind(symbol.st_info) != elf::sym::STB_LOCAL,
                object_file_index: Default::default(),
            }
        })
    }
}
