//! Helper for writing ELF files.
use std::mem;
use std::string::String;
use std::vec::Vec;

use crate::elf;
use crate::endian::*;
use crate::pod::bytes_of;
use crate::write::string::{StringId, StringTable};
use crate::write::util;
use crate::write::{Error, Result, WritableBuffer};

/// The index of an ELF section.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionIndex(pub u32);

/// The index of an ELF symbol.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolIndex(pub u32);

/// A helper for writing ELF files.
///
/// Writing uses a two phase approach. The first phase builds up all of
/// the information that may need to be known ahead of time:
/// - reserve file ranges for headers and sections
/// - reserve section indices
/// - reserve symbol indices
/// - build string tables
///
/// The second phase writes everything out in order.
#[allow(missing_debug_implementations)]
pub struct Writer<'a> {
    endian: Endianness,
    is_64: bool,
    elf: &'static dyn Elf,
    elf_align: usize,

    buffer: &'a mut dyn WritableBuffer,
    len: usize,

    section_offset: usize,
    section_num: u32,

    shstrtab: StringTable<'a>,
    shstrtab_str_id: Option<StringId>,
    shstrtab_index: SectionIndex,
    shstrtab_offset: usize,
    shstrtab_data: Vec<u8>,

    strtab: StringTable<'a>,
    strtab_str_id: Option<StringId>,
    strtab_index: SectionIndex,
    strtab_offset: usize,
    strtab_data: Vec<u8>,

    symtab_str_id: Option<StringId>,
    symtab_index: SectionIndex,
    symtab_offset: usize,
    symtab_num: u32,

    need_symtab_shndx: bool,
    symtab_shndx_str_id: Option<StringId>,
    symtab_shndx_offset: usize,
    symtab_shndx_data: Vec<u8>,

    dynstr: StringTable<'a>,
    dynstr_str_id: Option<StringId>,
    dynstr_index: SectionIndex,
    dynstr_offset: usize,
    dynstr_data: Vec<u8>,

    dynsym_str_id: Option<StringId>,
    dynsym_index: SectionIndex,
    dynsym_offset: usize,
    dynsym_num: u32,

    dynamic_str_id: Option<StringId>,
    dynamic_index: SectionIndex,
    dynamic_offset: usize,
    dynamic_num: usize,
}

impl<'a> Writer<'a> {
    /// Create a new `Writer` for the given endianness and ELF class.
    pub fn new(endian: Endianness, is_64: bool, buffer: &'a mut dyn WritableBuffer) -> Self {
        let elf: &'static dyn Elf = if is_64 { &Elf64 } else { &Elf32 };
        let elf_align = if is_64 { 8 } else { 4 };
        Writer {
            endian,
            is_64,
            elf,
            elf_align,

            buffer,
            len: 0,

            section_offset: 0,
            section_num: 0,

            shstrtab: StringTable::default(),
            shstrtab_str_id: None,
            shstrtab_index: SectionIndex(0),
            shstrtab_offset: 0,
            shstrtab_data: Vec::new(),

            strtab: StringTable::default(),
            strtab_str_id: None,
            strtab_index: SectionIndex(0),
            strtab_offset: 0,
            strtab_data: Vec::new(),

            symtab_str_id: None,
            symtab_index: SectionIndex(0),
            symtab_offset: 0,
            symtab_num: 0,

            need_symtab_shndx: false,
            symtab_shndx_str_id: None,
            symtab_shndx_offset: 0,
            symtab_shndx_data: Vec::new(),

            dynstr: StringTable::default(),
            dynstr_str_id: None,
            dynstr_index: SectionIndex(0),
            dynstr_offset: 0,
            dynstr_data: Vec::new(),

            dynsym_str_id: None,
            dynsym_index: SectionIndex(0),
            dynsym_offset: 0,
            dynsym_num: 0,

            dynamic_str_id: None,
            dynamic_index: SectionIndex(0),
            dynamic_offset: 0,
            dynamic_num: 0,
        }
    }

    /// Reserve a file range with the given size and starting alignment.
    ///
    /// Returns the aligned offset of the start of the range.
    pub fn reserve(&mut self, len: usize, align_start: usize) -> usize {
        if len == 0 {
            return self.len;
        }
        self.len = util::align(self.len, align_start);
        let offset = self.len;
        self.len += len;
        offset
    }

    /// Return the current file length that has been reserved.
    pub fn reserved_len(&self) -> usize {
        self.len()
    }

    /// Return the current file length that has been written.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Write alignment padding bytes.
    pub fn write_align(&mut self, align_start: usize) {
        util::write_align(self.buffer, align_start);
    }

    /// Write data.
    ///
    /// This is typically used to write section data.
    pub fn write(&mut self, data: &[u8]) {
        self.buffer.write_slice(data);
    }

    /// Reserve the range for the file header.
    ///
    /// This must be at the start of the file.
    pub fn reserve_file_header(&mut self) {
        debug_assert_eq!(self.len, 0);
        self.reserve(self.elf.file_header_size(), 1);
    }

    /// Write the file header.
    ///
    /// This must be at the start of the file.
    ///
    /// The caller should set the following fields if required, and
    /// use `Ident::default() and `FileHeader::default()` for the remainder:
    /// `e_ident.os_abi`, `e_ident.abi_version`, `e_type`, `e_machine`, `e_entry`, `e_flags
    ///
    /// Fields that can be derived from known information are automatically set by this function.
    pub fn write_file_header(&mut self, mut header: FileHeader) -> Result<()> {
        debug_assert_eq!(self.buffer.len(), 0);

        // Start writing.
        self.buffer
            .reserve(self.len)
            .map_err(|_| Error(String::from("Cannot allocate buffer")))?;

        // Write file header.
        header.e_ident.class = if self.is_64 {
            elf::ELFCLASS64
        } else {
            elf::ELFCLASS32
        };
        header.e_ident.data = if self.endian.is_little_endian() {
            elf::ELFDATA2LSB
        } else {
            elf::ELFDATA2MSB
        };

        header.e_ehsize = self.elf.file_header_size() as u16;

        header.e_shoff = self.section_offset as u64;
        header.e_shentsize = self.elf.section_header_size() as u16;
        header.e_shnum = if self.section_num >= elf::SHN_LORESERVE.into() {
            0
        } else {
            self.section_num as u16
        };
        header.e_shstrndx = if self.shstrtab_index.0 >= elf::SHN_LORESERVE.into() {
            elf::SHN_XINDEX
        } else {
            self.shstrtab_index.0 as u16
        };

        self.elf.write_file_header(self.buffer, self.endian, header);
        Ok(())
    }

    /// Reserve a section table index.
    ///
    /// Automatically also reserves the null section header if required.
    ///
    /// This must not be called after [`Self::reserve_section_headers`].
    pub fn reserve_section(&mut self) -> SectionIndex {
        debug_assert_eq!(self.section_offset, 0);
        if self.section_num == 0 {
            self.section_num = 1;
        }
        let index = self.section_num;
        self.section_num += 1;
        SectionIndex(index)
    }

    /// Reserve the range for the section headers.
    ///
    /// This function does nothing if no sections were reserved.
    pub fn reserve_section_headers(&mut self) {
        debug_assert_eq!(self.section_offset, 0);
        if self.section_num == 0 {
            return;
        }
        self.section_offset = self.reserve(
            self.section_num as usize * self.elf.section_header_size(),
            self.elf_align,
        );
    }

    /// Write the null section header.
    ///
    /// This must be the first section header that is written.
    /// This function does nothing if no sections were reserved.
    pub fn write_null_section_header(&mut self) {
        if self.section_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.section_offset, self.buffer.len());
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: if self.section_num >= elf::SHN_LORESERVE.into() {
                    self.section_num.into()
                } else {
                    0
                },
                sh_link: if self.shstrtab_index.0 >= elf::SHN_LORESERVE.into() {
                    self.shstrtab_index.0
                } else {
                    0
                },
                // TODO: e_phnum overflow
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        );
    }

    /// Write a section header.
    pub fn write_section_header(&mut self, name: Option<StringId>, mut section: SectionHeader) {
        if let Some(name) = name {
            section.sh_name = self.shstrtab.get_offset(name) as u32;
        }
        self.elf
            .write_section_header(self.buffer, self.endian, section);
    }

    /// Add a section name to the section header string table.
    ///
    /// This will be stored in the `.shstrtab` section.
    ///
    /// This must not be called after [`Self::reserve_shstrtab`].
    pub fn section_name(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.shstrtab_offset, 0);
        self.shstrtab.add(name)
    }

    /// Reserve the range for the section header string table.
    ///
    /// This range is used for a section named `.shstrtab`.
    /// This also reserves a section index.
    /// This function does nothing if no sections were reserved.
    pub fn reserve_shstrtab(&mut self) {
        debug_assert_eq!(self.shstrtab_offset, 0);
        if self.section_num == 0 {
            return;
        }
        self.shstrtab_str_id = Some(self.section_name(&b".shstrtab"[..]));
        // Start with null section name.
        self.shstrtab_data = vec![0];
        self.shstrtab.write(1, &mut self.shstrtab_data);
        self.shstrtab_index = self.reserve_section();
        self.shstrtab_offset = self.reserve(self.shstrtab_data.len(), 1);
    }

    /// Write the section header string table.
    ///
    /// This function does nothing if no sections were reserved.
    pub fn write_shstrtab(&mut self) {
        if self.section_num == 0 {
            return;
        }
        debug_assert_eq!(self.shstrtab_offset, self.buffer.len());
        self.buffer.write_slice(&self.shstrtab_data);
    }

    /// Write the section header for the section header string table.
    ///
    /// This function does nothing if no sections were reserved.
    pub fn write_shstrtab_section_header(&mut self) {
        if self.section_num == 0 {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.shstrtab_str_id.unwrap()) as u32,
                sh_type: elf::SHT_STRTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: self.shstrtab_offset as u64,
                sh_size: self.shstrtab_data.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            },
        );
    }

    /// Add a string to the string table.
    ///
    /// This will be stored in the `.strtab` section.
    ///
    /// This must not be called after [`Self::reserve_strtab`].
    pub fn string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.strtab_offset, 0);
        self.strtab.add(name)
    }

    /// Reserve the range for the string table.
    ///
    /// This range is used for a section named `.strtab`.
    /// This also reserves a section index.
    /// This function does nothing if no strings were defined.
    pub fn reserve_strtab(&mut self) {
        debug_assert_eq!(self.strtab_offset, 0);
        if self.strtab.is_empty() {
            return;
        }
        self.strtab_str_id = Some(self.section_name(&b".strtab"[..]));
        // Start with null string.
        self.strtab_data = vec![0];
        self.strtab.write(1, &mut self.strtab_data);
        self.strtab_index = self.reserve_section();
        self.strtab_offset = self.reserve(self.strtab_data.len(), 1);
    }

    /// Write the string table.
    ///
    /// This function does nothing if no strings were defined.
    pub fn write_strtab(&mut self) {
        if self.strtab.is_empty() {
            return;
        }
        debug_assert_eq!(self.strtab_offset, self.buffer.len());
        self.buffer.write_slice(&self.strtab_data);
    }

    /// Write the section header for the string table.
    ///
    /// This function does nothing if no strings were defined.
    pub fn write_strtab_section_header(&mut self) {
        if self.strtab.is_empty() {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.strtab_str_id.unwrap()) as u32,
                sh_type: elf::SHT_STRTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: self.strtab_offset as u64,
                sh_size: self.strtab_data.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            },
        );
    }

    /// Return the number of reserved symbol table entries.
    pub fn symtab_num(&self) -> u32 {
        self.symtab_num
    }

    /// Reserve a symbol table entry.
    ///
    /// This will be stored in the `.symtab` section.
    ///
    /// `section_index` is used to determine whether `.symtab_shndx` is required.
    ///
    /// Automatically also reserves the null symbol if required.
    pub fn reserve_symbol(&mut self, section_index: Option<SectionIndex>) -> SymbolIndex {
        debug_assert_eq!(self.symtab_offset, 0);
        debug_assert_eq!(self.symtab_shndx_offset, 0);
        if self.symtab_num == 0 {
            self.symtab_num = 1;
        }
        let index = self.symtab_num;
        self.symtab_num += 1;
        if let Some(section_index) = section_index {
            if section_index.0 >= elf::SHN_LORESERVE.into() {
                self.need_symtab_shndx = true;
            }
        }
        SymbolIndex(index)
    }

    /// Write the null symbol.
    ///
    /// This must be the first symbol that is written.
    /// This function does nothing if no symbols were reserved.
    pub fn write_null_symbol(&mut self) {
        if self.symtab_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.symtab_offset, self.buffer.len());
        self.elf.write_symbol(
            self.buffer,
            self.endian,
            Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
        );
        if self.need_symtab_shndx {
            self.symtab_shndx_data
                .extend_from_slice(bytes_of(&U32::new(self.endian, 0)));
        }
    }

    /// Write a symbol.
    pub fn write_symbol(
        &mut self,
        name: Option<StringId>,
        section_index: Option<SectionIndex>,
        mut sym: Sym,
    ) {
        if let Some(name) = name {
            sym.st_name = self.strtab.get_offset(name) as u32;
        }
        if let Some(section_index) = section_index {
            sym.st_shndx = if section_index.0 >= elf::SHN_LORESERVE as u32 {
                elf::SHN_XINDEX
            } else {
                section_index.0 as u16
            };
        }
        self.elf.write_symbol(self.buffer, self.endian, sym);
        if self.need_symtab_shndx {
            let section_index = section_index.unwrap_or(SectionIndex(0));
            self.symtab_shndx_data
                .extend_from_slice(bytes_of(&U32::new(self.endian, section_index.0)));
        }
    }

    /// Reserve the range for the symbol table.
    ///
    /// This range is used for a section named `.symtab`.
    /// This also reserves a section index.
    /// This function does nothing if no symbols were reserved.
    pub fn reserve_symtab(&mut self) {
        debug_assert_eq!(self.symtab_offset, 0);
        if self.symtab_num == 0 {
            return;
        }
        self.symtab_str_id = Some(self.section_name(&b".symtab"[..]));
        self.symtab_index = self.reserve_section();
        self.symtab_offset = self.reserve(
            self.symtab_num as usize * self.elf.symbol_size(),
            self.elf_align,
        );
    }

    /// Return the section index of the symbol table.
    pub fn symtab_index(&mut self) -> SectionIndex {
        self.symtab_index
    }

    /// Write the section header for the symbol table.
    /// This function does nothing if no symbols were reserved.
    pub fn write_symtab_section_header(&mut self, num_local: u32) {
        if self.symtab_num == 0 {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.symtab_str_id.unwrap()) as u32,
                sh_type: elf::SHT_SYMTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: self.symtab_offset as u64,
                sh_size: self.symtab_num as u64 * self.elf.symbol_size() as u64,
                sh_link: self.strtab_index.0,
                sh_info: num_local,
                sh_addralign: self.elf_align as u64,
                sh_entsize: self.elf.symbol_size() as u64,
            },
        );
    }

    /// Reserve the range for the extended section indices for the symbol table.
    ///
    /// This range is used for a section named `.symtab_shndx`.
    /// This also reserves a section index.
    ///
    /// This function does nothing if extended section indices are not needed.
    pub fn reserve_symtab_shndx(&mut self) {
        debug_assert_eq!(self.symtab_shndx_offset, 0);
        if !self.need_symtab_shndx {
            return;
        }
        self.symtab_shndx_str_id = Some(self.section_name(&b".symtab_shndx"[..]));
        self.reserve_section();
        self.symtab_shndx_offset = self.reserve(self.symtab_num as usize * 4, 4);
    }

    /// Write the extended section indices for the symbol table.
    ///
    /// This function does nothing if extended section indices are not needed.
    pub fn write_symtab_shndx(&mut self) {
        if !self.need_symtab_shndx {
            return;
        }
        debug_assert_eq!(self.symtab_shndx_offset, self.buffer.len());
        debug_assert_eq!(self.symtab_num as usize * 4, self.symtab_shndx_data.len());
        self.buffer.write_slice(&self.symtab_shndx_data);
    }

    /// Write the section header for the extended section indices for the symbol table.
    pub fn write_symtab_shndx_section_header(&mut self) {
        if !self.need_symtab_shndx {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.symtab_shndx_str_id.unwrap()) as u32,
                sh_type: elf::SHT_SYMTAB_SHNDX,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: self.symtab_shndx_offset as u64,
                sh_size: (self.symtab_num * 4) as u64,
                sh_link: self.symtab_index.0,
                sh_info: 0,
                sh_addralign: 4,
                sh_entsize: 4,
            },
        );
    }

    /// Add a string to the dynamic string table.
    ///
    /// This will be stored in the `.dynstr` section.
    ///
    /// This must not be called after [`Self::reserve_dynstr`].
    pub fn dynamic_string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.dynstr_offset, 0);
        self.dynstr.add(name)
    }

    /// Reserve the range for the dynamic string table.
    ///
    /// This range is used for a section named `.dynstr`.
    /// This also reserves a section index.
    /// This function does nothing if no strings were defined.
    pub fn reserve_dynstr(&mut self) {
        debug_assert_eq!(self.dynstr_offset, 0);
        if self.dynstr.is_empty() {
            return;
        }
        self.dynstr_str_id = Some(self.section_name(&b".dynstr"[..]));
        // Start with null string.
        self.dynstr_data = vec![0];
        self.dynstr.write(1, &mut self.dynstr_data);
        self.dynstr_index = self.reserve_section();
        self.dynstr_offset = self.reserve(self.dynstr_data.len(), 1);
    }

    /// Write the dynamic string table.
    ///
    /// This function does nothing if no strings were defined.
    pub fn write_dynstr(&mut self) {
        if self.dynstr.is_empty() {
            return;
        }
        debug_assert_eq!(self.dynstr_offset, self.buffer.len());
        self.buffer.write_slice(&self.dynstr_data);
    }

    /// Write the section header for the dynamic string table.
    ///
    /// This function does nothing if no strings were defined.
    pub fn write_dynstr_section_header(&mut self) {
        if self.dynstr.is_empty() {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.dynstr_str_id.unwrap()) as u32,
                sh_type: elf::SHT_STRTAB,
                sh_flags: elf::SHF_ALLOC.into(),
                sh_addr: 0,
                sh_offset: self.dynstr_offset as u64,
                sh_size: self.dynstr_data.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            },
        );
    }

    /// Reserve a dynamic symbol table entry.
    ///
    /// This will be stored in the `.dynsym` section.
    ///
    /// Automatically also reserves the null symbol if required.
    pub fn reserve_dynamic_symbol(&mut self) -> SymbolIndex {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            self.dynsym_num = 1;
        }
        let index = self.dynsym_num;
        self.dynsym_num += 1;
        SymbolIndex(index)
    }

    /// Write the null dynamic symbol.
    ///
    /// This must be the first dynamic symbol that is written.
    /// This function does nothing if no dynamic symbols were reserved.
    pub fn write_null_dynamic_symbol(&mut self) {
        if self.dynsym_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.dynsym_offset, self.buffer.len());
        self.elf.write_symbol(
            self.buffer,
            self.endian,
            Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
        );
    }

    /// Write a dynamic symbol.
    pub fn write_dynamic_symbol(&mut self, name: Option<StringId>, mut sym: Sym) {
        if let Some(name) = name {
            sym.st_name = self.dynstr.get_offset(name) as u32;
        }
        self.elf.write_symbol(self.buffer, self.endian, sym);
    }

    /// Reserve the range for the dynamic symbol table.
    ///
    /// This range is used for a section named `.dynsym`.
    /// This also reserves a section index.
    /// This function does nothing if no dynamic symbols were reserved.
    pub fn reserve_dynsym(&mut self) {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            return;
        }
        self.dynsym_str_id = Some(self.section_name(&b".dynsym"[..]));
        self.dynsym_index = self.reserve_section();
        self.dynsym_offset = self.reserve(
            self.dynsym_num as usize * self.elf.symbol_size(),
            self.elf_align,
        );
    }

    /// Return the section index of the dynamic symbol table.
    pub fn dynsym_index(&mut self) -> SectionIndex {
        self.dynsym_index
    }

    /// Write the section header for the dynamic symbol table.
    /// This function does nothing if no dynamic symbols were reserved.
    pub fn write_dynsym_section_header(&mut self, num_local: u32) {
        if self.dynsym_num == 0 {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.dynsym_str_id.unwrap()) as u32,
                sh_type: elf::SHT_DYNSYM,
                sh_flags: elf::SHF_ALLOC.into(),
                sh_addr: 0,
                sh_offset: self.dynsym_offset as u64,
                sh_size: self.dynsym_num as u64 * self.elf.symbol_size() as u64,
                sh_link: self.dynstr_index.0,
                sh_info: num_local,
                sh_addralign: self.elf_align as u64,
                sh_entsize: self.elf.symbol_size() as u64,
            },
        );
    }

    /// Reserve the range for the `.dynamic` section.
    ///
    /// This also reserves a section index.
    pub fn reserve_dynamic(&mut self, dynamic_num: usize) {
        debug_assert_eq!(self.dynamic_offset, 0);
        if dynamic_num == 0 {
            return;
        }
        self.dynamic_str_id = Some(self.section_name(&b".dynamic"[..]));
        self.dynamic_index = self.reserve_section();
        self.dynamic_num = dynamic_num;
        self.dynamic_offset = self.reserve(
            self.dynamic_num as usize * self.elf.dyn_size(),
            self.elf_align,
        );
    }

    /// Write alignment padding bytes prior to the `.dynamic` section.
    pub fn write_align_dynamic(&mut self) {
        if self.dynamic_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.dynamic_offset, self.buffer.len());
    }

    /// Write a dynamic string entry.
    pub fn write_dynamic_string(&mut self, tag: u64, id: StringId) {
        self.write_dynamic(tag, self.dynstr.get_offset(id) as u64);
    }

    /// Write a dynamic value entry.
    pub fn write_dynamic(&mut self, tag: u64, val: u64) {
        debug_assert!(self.dynamic_offset <= self.buffer.len());
        self.elf.write_dyn(
            self.buffer,
            self.endian,
            Dyn {
                d_tag: tag,
                d_val: val,
            },
        );
        debug_assert!(
            self.dynamic_offset + self.dynamic_num * self.elf.dyn_size() >= self.buffer.len()
        );
    }

    /// Write the section header for the dynamic table.
    ///
    /// This function does nothing if no dynamic entries were reserved.
    pub fn write_dynamic_section_header(&mut self) {
        if self.dynamic_num == 0 {
            return;
        }
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(self.dynamic_str_id.unwrap()) as u32,
                sh_type: elf::SHT_DYNAMIC,
                sh_flags: (elf::SHF_WRITE | elf::SHF_ALLOC).into(),
                // FIXME
                sh_addr: 0,
                sh_offset: self.dynamic_offset as u64,
                sh_size: self.dynamic_num as u64 * self.elf.dyn_size() as u64,
                sh_link: self.dynstr_index.0,
                sh_info: 0,
                sh_addralign: self.elf_align as u64,
                sh_entsize: self.elf.dyn_size() as u64,
            },
        );
    }

    /// Reserve a file range for the given number of relocations.
    ///
    /// Returns the offset of the range.
    pub fn reserve_relocations(&mut self, count: usize, is_rela: bool) -> usize {
        self.reserve(count * self.elf.rel_size(is_rela), self.elf_align)
    }

    /// Write alignment padding bytes prior to a relocation section.
    pub fn write_align_relocation(&mut self) {
        util::write_align(self.buffer, self.elf_align);
    }

    /// Write a relocation.
    pub fn write_relocation(&mut self, is_mips64el: bool, is_rela: bool, rel: Rel) {
        self.elf
            .write_rel(self.buffer, self.endian, is_mips64el, is_rela, rel);
    }

    /// Write the section header for a relocation section.
    ///
    /// `section` is the index of the section the relocations apply to,
    /// or 0 if none.
    ///
    /// `offset` is the file offset of the relocations.
    pub fn write_relocation_section_header(
        &mut self,
        name: StringId,
        section: SectionIndex,
        offset: usize,
        count: usize,
        is_rela: bool,
    ) {
        self.elf.write_section_header(
            self.buffer,
            self.endian,
            SectionHeader {
                sh_name: self.shstrtab.get_offset(name) as u32,
                sh_type: if is_rela { elf::SHT_RELA } else { elf::SHT_REL },
                sh_flags: elf::SHF_INFO_LINK.into(),
                sh_addr: 0,
                sh_offset: offset as u64,
                sh_size: (count * self.elf.rel_size(is_rela)) as u64,
                // TODO: allow dynsym
                sh_link: self.symtab_index.0,
                sh_info: section.0,
                sh_addralign: self.elf_align as u64,
                sh_entsize: self.elf.rel_size(is_rela) as u64,
            },
        );
    }
}

/// Native endian version of [`elf::FileHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub e_ident: elf::Ident,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Default for elf::Ident {
    fn default() -> Self {
        elf::Ident {
            magic: elf::ELFMAG,
            class: elf::ELFCLASSNONE,
            data: elf::ELFDATANONE,
            version: elf::EV_CURRENT,
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            padding: [0; 7],
        }
    }
}
impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            e_ident: elf::Ident::default(),
            e_type: elf::ET_NONE,
            e_machine: elf::EM_NONE,
            e_version: elf::EV_CURRENT.into(),
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

/// Native endian version of [`elf::SectionHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Native endian version of [`elf::Sym64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

/// Native endian version of [`elf::Dyn64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Dyn {
    pub d_tag: u64,
    pub d_val: u64,
}

/// Unified native endian version of [`elf::Rel64`] and [`elf::Rela64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Rel {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
    pub r_addend: i64,
}

trait Elf {
    fn file_header_size(&self) -> usize;
    fn section_header_size(&self) -> usize;
    fn symbol_size(&self) -> usize;
    fn dyn_size(&self) -> usize;
    fn rel_size(&self, is_rela: bool) -> usize;
    fn write_file_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        section: FileHeader,
    );
    fn write_section_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        section: SectionHeader,
    );
    fn write_dyn(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, d: Dyn);
    fn write_symbol(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, symbol: Sym);
    fn write_rel(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        is_mips64el: bool,
        is_rela: bool,
        rel: Rel,
    );
}

struct Elf32;

impl Elf for Elf32 {
    fn file_header_size(&self) -> usize {
        mem::size_of::<elf::FileHeader32<Endianness>>()
    }

    fn section_header_size(&self) -> usize {
        mem::size_of::<elf::SectionHeader32<Endianness>>()
    }

    fn symbol_size(&self) -> usize {
        mem::size_of::<elf::Sym32<Endianness>>()
    }

    fn dyn_size(&self) -> usize {
        mem::size_of::<elf::Dyn32<Endianness>>()
    }

    fn rel_size(&self, is_rela: bool) -> usize {
        if is_rela {
            mem::size_of::<elf::Rela32<Endianness>>()
        } else {
            mem::size_of::<elf::Rel32<Endianness>>()
        }
    }

    fn write_file_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        file: FileHeader,
    ) {
        let file = elf::FileHeader32 {
            e_ident: file.e_ident,
            e_type: U16::new(endian, file.e_type),
            e_machine: U16::new(endian, file.e_machine),
            e_version: U32::new(endian, file.e_version),
            e_entry: U32::new(endian, file.e_entry as u32),
            e_phoff: U32::new(endian, file.e_phoff as u32),
            e_shoff: U32::new(endian, file.e_shoff as u32),
            e_flags: U32::new(endian, file.e_flags),
            e_ehsize: U16::new(endian, file.e_ehsize),
            e_phentsize: U16::new(endian, file.e_phentsize),
            e_phnum: U16::new(endian, file.e_phnum),
            e_shentsize: U16::new(endian, file.e_shentsize),
            e_shnum: U16::new(endian, file.e_shnum),
            e_shstrndx: U16::new(endian, file.e_shstrndx),
        };
        buffer.write(&file);
    }

    fn write_section_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        section: SectionHeader,
    ) {
        let section = elf::SectionHeader32 {
            sh_name: U32::new(endian, section.sh_name),
            sh_type: U32::new(endian, section.sh_type),
            sh_flags: U32::new(endian, section.sh_flags as u32),
            sh_addr: U32::new(endian, section.sh_addr as u32),
            sh_offset: U32::new(endian, section.sh_offset as u32),
            sh_size: U32::new(endian, section.sh_size as u32),
            sh_link: U32::new(endian, section.sh_link),
            sh_info: U32::new(endian, section.sh_info),
            sh_addralign: U32::new(endian, section.sh_addralign as u32),
            sh_entsize: U32::new(endian, section.sh_entsize as u32),
        };
        buffer.write(&section);
    }

    fn write_dyn(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, d: Dyn) {
        let d = elf::Dyn32 {
            d_tag: U32::new(endian, d.d_tag as u32),
            d_val: U32::new(endian, d.d_val as u32),
        };
        buffer.write(&d);
    }

    fn write_symbol(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, symbol: Sym) {
        let symbol = elf::Sym32 {
            st_name: U32::new(endian, symbol.st_name),
            st_info: symbol.st_info,
            st_other: symbol.st_other,
            st_shndx: U16::new(endian, symbol.st_shndx),
            st_value: U32::new(endian, symbol.st_value as u32),
            st_size: U32::new(endian, symbol.st_size as u32),
        };
        buffer.write(&symbol);
    }

    fn write_rel(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        _is_mips64el: bool,
        is_rela: bool,
        rel: Rel,
    ) {
        if is_rela {
            let rel = elf::Rela32 {
                r_offset: U32::new(endian, rel.r_offset as u32),
                r_info: elf::Rel32::r_info(endian, rel.r_sym, rel.r_type as u8),
                r_addend: I32::new(endian, rel.r_addend as i32),
            };
            buffer.write(&rel);
        } else {
            let rel = elf::Rel32 {
                r_offset: U32::new(endian, rel.r_offset as u32),
                r_info: elf::Rel32::r_info(endian, rel.r_sym, rel.r_type as u8),
            };
            buffer.write(&rel);
        }
    }
}

struct Elf64;

impl Elf for Elf64 {
    fn file_header_size(&self) -> usize {
        mem::size_of::<elf::FileHeader64<Endianness>>()
    }

    fn section_header_size(&self) -> usize {
        mem::size_of::<elf::SectionHeader64<Endianness>>()
    }

    fn symbol_size(&self) -> usize {
        mem::size_of::<elf::Sym64<Endianness>>()
    }

    fn dyn_size(&self) -> usize {
        mem::size_of::<elf::Dyn64<Endianness>>()
    }

    fn rel_size(&self, is_rela: bool) -> usize {
        if is_rela {
            mem::size_of::<elf::Rela64<Endianness>>()
        } else {
            mem::size_of::<elf::Rel64<Endianness>>()
        }
    }

    fn write_file_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        file: FileHeader,
    ) {
        let file = elf::FileHeader64 {
            e_ident: file.e_ident,
            e_type: U16::new(endian, file.e_type),
            e_machine: U16::new(endian, file.e_machine),
            e_version: U32::new(endian, file.e_version),
            e_entry: U64::new(endian, file.e_entry),
            e_phoff: U64::new(endian, file.e_phoff),
            e_shoff: U64::new(endian, file.e_shoff),
            e_flags: U32::new(endian, file.e_flags),
            e_ehsize: U16::new(endian, file.e_ehsize),
            e_phentsize: U16::new(endian, file.e_phentsize),
            e_phnum: U16::new(endian, file.e_phnum),
            e_shentsize: U16::new(endian, file.e_shentsize),
            e_shnum: U16::new(endian, file.e_shnum),
            e_shstrndx: U16::new(endian, file.e_shstrndx),
        };
        buffer.write(&file)
    }

    fn write_section_header(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        section: SectionHeader,
    ) {
        let section = elf::SectionHeader64 {
            sh_name: U32::new(endian, section.sh_name),
            sh_type: U32::new(endian, section.sh_type),
            sh_flags: U64::new(endian, section.sh_flags),
            sh_addr: U64::new(endian, section.sh_addr),
            sh_offset: U64::new(endian, section.sh_offset),
            sh_size: U64::new(endian, section.sh_size),
            sh_link: U32::new(endian, section.sh_link),
            sh_info: U32::new(endian, section.sh_info),
            sh_addralign: U64::new(endian, section.sh_addralign),
            sh_entsize: U64::new(endian, section.sh_entsize),
        };
        buffer.write(&section);
    }

    fn write_dyn(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, d: Dyn) {
        let d = elf::Dyn64 {
            d_tag: U64::new(endian, d.d_tag),
            d_val: U64::new(endian, d.d_val),
        };
        buffer.write(&d);
    }

    fn write_symbol(&self, buffer: &mut dyn WritableBuffer, endian: Endianness, symbol: Sym) {
        let symbol = elf::Sym64 {
            st_name: U32::new(endian, symbol.st_name),
            st_info: symbol.st_info,
            st_other: symbol.st_other,
            st_shndx: U16::new(endian, symbol.st_shndx),
            st_value: U64::new(endian, symbol.st_value),
            st_size: U64::new(endian, symbol.st_size),
        };
        buffer.write(&symbol);
    }

    fn write_rel(
        &self,
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        is_mips64el: bool,
        is_rela: bool,
        rel: Rel,
    ) {
        if is_rela {
            let rel = elf::Rela64 {
                r_offset: U64::new(endian, rel.r_offset),
                r_info: elf::Rela64::r_info2(endian, is_mips64el, rel.r_sym, rel.r_type),
                r_addend: I64::new(endian, rel.r_addend),
            };
            buffer.write(&rel);
        } else {
            let rel = elf::Rel64 {
                r_offset: U64::new(endian, rel.r_offset),
                r_info: elf::Rel64::r_info(endian, rel.r_sym, rel.r_type),
            };
            buffer.write(&rel);
        }
    }
}
