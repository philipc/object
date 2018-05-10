//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`File` struct](./struct.File.html) for details.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#![no_std]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate core as std;
#[cfg(not(feature = "std"))]
extern crate alloc;

extern crate goblin;
extern crate uuid;

#[cfg(feature = "std")]
mod alloc {
    pub use std::borrow;
    pub use std::vec;
}

use std::fmt;
use alloc::vec::Vec;

mod elf;
pub use elf::*;

mod macho;
pub use macho::*;

mod pe;
pub use pe::*;

mod traits;
pub use traits::*;

pub use uuid::Uuid;

/// An object file.
#[derive(Debug)]
pub struct File<'data> {
    inner: FileInternal<'data>,
}

#[derive(Debug)]
enum FileInternal<'data> {
    Elf(ElfFile<'data>),
    MachO(MachOFile<'data>),
    Pe(PeFile<'data>),
}

/// The machine type of an object file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    /// An unrecognized machine type.
    Other,
    /// ARM
    Arm,
    /// ARM64
    Arm64,
    /// x86
    X86,
    /// x86-64
    #[allow(non_camel_case_types)]
    X86_64,
}

/// Information from an object file that can be used to locate separate debug info.
#[derive(Debug, Clone, Copy)]
pub enum DebugFileInfo {
    /// The UUID from a Mach-O `LC_UUID` load command.
    MachOUuid(Uuid),
}

/// An iterator over the segments of a `File`.
#[derive(Debug)]
pub struct SegmentIterator<'data, 'file>
where
    'data: 'file,
{
    inner: SegmentIteratorInternal<'data, 'file>,
}

#[derive(Debug)]
enum SegmentIteratorInternal<'data, 'file>
where
    'data: 'file,
{
    Elf(ElfSegmentIterator<'data, 'file>),
    MachO(MachOSegmentIterator<'data, 'file>),
    Pe(PeSegmentIterator<'data, 'file>),
}

/// A segment of a `File`.
pub struct Segment<'data, 'file>
where
    'data: 'file,
{
    inner: SegmentInternal<'data, 'file>,
}

#[derive(Debug)]
enum SegmentInternal<'data, 'file>
where
    'data: 'file,
{
    Elf(ElfSegment<'data, 'file>),
    MachO(MachOSegment<'data, 'file>),
    Pe(PeSegment<'data, 'file>),
}

/// An iterator of the sections of a `File`.
#[derive(Debug)]
pub struct SectionIterator<'data, 'file>
where
    'data: 'file,
{
    inner: SectionIteratorInternal<'data, 'file>,
}

// we wrap our enums in a struct so that they are kept private.
#[derive(Debug)]
enum SectionIteratorInternal<'data, 'file>
where
    'data: 'file,
{
    Elf(ElfSectionIterator<'data, 'file>),
    MachO(MachOSectionIterator<'data, 'file>),
    Pe(PeSectionIterator<'data, 'file>),
}

/// A Section of a File
pub struct Section<'data, 'file>
where
    'data: 'file,
{
    inner: SectionInternal<'data, 'file>,
}

enum SectionInternal<'data, 'file>
where
    'data: 'file,
{
    Elf(ElfSection<'data, 'file>),
    MachO(MachOSection<'data>),
    Pe(PeSection<'data, 'file>),
}

/// The kind of a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// The section kind is unknown.
    Unknown,
    /// An executable code section.
    Text,
    /// A data section.
    Data,
    /// A read only data section.
    ReadOnlyData,
    /// An uninitialized data section.
    UninitializedData,
    /// Some other type of text or data section.
    Other,
}

/// An iterator over symbol table entries.
#[derive(Debug)]
pub struct SymbolIterator<'data, 'file>
where
    'data: 'file,
{
    inner: SymbolIteratorInternal<'data, 'file>,
}

#[derive(Debug)]
enum SymbolIteratorInternal<'data, 'file>
where
    'data: 'file,
{
    Elf(ElfSymbolIterator<'data, 'file>),
    MachO(MachOSymbolIterator<'data>),
    Pe(PeSymbolIterator<'data, 'file>),
}

/// A symbol table entry.
#[derive(Debug)]
pub struct Symbol<'data> {
    name: Option<&'data str>,
    address: u64,
    size: u64,
    kind: SymbolKind,
    section_kind: Option<SectionKind>,
    global: bool,
    object_file_index: SymbolObjectFileIndex,
}

/// The kind of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// The symbol kind is unknown.
    Unknown,
    /// The symbol is for executable code.
    Text,
    /// The symbol is for a data object.
    Data,
    /// The symbol is for a section.
    Section,
    /// The symbol is the name of a file. It precedes symbols within that file.
    File,
    /// The symbol is for an uninitialized common block.
    Common,
    /// The symbol is for a thread local storage entity.
    Tls,
}

/// A source object file for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolObjectFile<'data> {
    /// The path to the object file. This may include an archive member name.
    // TODO: add helpers to split archive member name
    pub path: &'data str,
    /// The timestamp of the source object file.
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SymbolObjectFileIndex(usize);

/// A map from addresses to symbols.
#[derive(Debug)]
pub struct SymbolMap<'data> {
    symbols: Vec<Symbol<'data>>,
    object_files: Vec<SymbolObjectFile<'data>>,
}

/// Evaluate an expression on the contents of a file format enum.
///
/// This is a hack to avoid virtual calls.
macro_rules! with_inner {
    ($inner:expr, $enum:ident, |$var:ident| $body:expr) => {
        match $inner {
            $enum::Elf(ref $var) => { $body }
            $enum::MachO(ref $var) => { $body }
            $enum::Pe(ref $var) => { $body }
        }
    }
}

macro_rules! with_inner_mut {
    ($inner:expr, $enum:ident, |$var:ident| $body:expr) => {
        match $inner {
            $enum::Elf(ref mut $var) => { $body }
            $enum::MachO(ref mut $var) => { $body }
            $enum::Pe(ref mut $var) => { $body }
        }
    }
}

/// Like `with_inner!`, but wraps the result in another enum.
macro_rules! map_inner {
    ($inner:expr, $from:ident, $to:ident, |$var:ident| $body:expr) => {
        match $inner {
            $from::Elf(ref $var) => $to::Elf($body),
            $from::MachO(ref $var) => $to::MachO($body),
            $from::Pe(ref $var) => $to::Pe($body),
        }
    }
}

/// Call `next` for a file format iterator.
macro_rules! next_inner {
    ($inner:expr, $from:ident, $to:ident) => {
        match $inner {
            $from::Elf(ref mut iter) => iter.next().map($to::Elf),
            $from::MachO(ref mut iter) => iter.next().map($to::MachO),
            $from::Pe(ref mut iter) => iter.next().map($to::Pe),
        }
    }
}

impl<'data> File<'data> {
    /// Parse the raw file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("File too short");
        }
        let mut bytes = [0u8; 16];
        bytes.clone_from_slice(&data[..16]);
        let inner = match goblin::peek_bytes(&bytes).map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => FileInternal::Elf(ElfFile::parse(data)?),
            goblin::Hint::Mach(_) => FileInternal::MachO(MachOFile::parse(data)?),
            goblin::Hint::PE => FileInternal::Pe(PeFile::parse(data)?),
            _ => return Err("Unknown file magic"),
        };
        Ok(File { inner })
    }
}

impl<'data, 'file> Object<'data, 'file> for File<'data>
where
    'data: 'file,
{
    type Segment = Segment<'data, 'file>;
    type SegmentIterator = SegmentIterator<'data, 'file>;
    type Section = Section<'data, 'file>;
    type SectionIterator = SectionIterator<'data, 'file>;
    type SymbolIterator = SymbolIterator<'data, 'file>;

    fn machine(&self) -> Machine {
        with_inner!(self.inner, FileInternal, |x| x.machine())
    }

    fn segments(&'file self) -> SegmentIterator<'data, 'file> {
        SegmentIterator {
            inner: map_inner!(self.inner, FileInternal, SegmentIteratorInternal, |x| {
                x.segments()
            }),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]> {
        with_inner!(self.inner, FileInternal, |x| {
            x.section_data_by_name(section_name)
        })
    }

    fn sections(&'file self) -> SectionIterator<'data, 'file> {
        SectionIterator {
            inner: map_inner!(self.inner, FileInternal, SectionIteratorInternal, |x| {
                x.sections()
            }),
        }
    }

    fn symbols(&'file self) -> SymbolIterator<'data, 'file> {
        SymbolIterator {
            inner: map_inner!(self.inner, FileInternal, SymbolIteratorInternal, |x| {
                x.symbols()
            }),
        }
    }

    fn dynamic_symbols(&'file self) -> SymbolIterator<'data, 'file> {
        SymbolIterator {
            inner: map_inner!(self.inner, FileInternal, SymbolIteratorInternal, |x| {
                x.dynamic_symbols()
            }),
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        with_inner!(self.inner, FileInternal, |x| x.symbol_map())
    }

    fn is_little_endian(&self) -> bool {
        with_inner!(self.inner, FileInternal, |x| x.is_little_endian())
    }

    fn has_debug_symbols(&self) -> bool {
        with_inner!(self.inner, FileInternal, |x| x.has_debug_symbols())
    }

    fn debug_file_info(&self) -> Option<DebugFileInfo> {
        with_inner!(self.inner, FileInternal, |x| x.debug_file_info())
    }

    fn entry(&self) -> u64 {
        with_inner!(self.inner, FileInternal, |x| x.entry())
    }
}

impl<'data, 'file> Iterator for SegmentIterator<'data, 'file> {
    type Item = Segment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        next_inner!(self.inner, SegmentIteratorInternal, SegmentInternal)
            .map(|inner| Segment { inner })
    }
}

impl<'data, 'file> fmt::Debug for Segment<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("Segment")
            .field("name", &self.name().unwrap_or("<unnamed>"))
            .field("address", &self.address())
            .field("size", &self.data().len())
            .finish()
    }
}

impl<'data, 'file> ObjectSegment<'data> for Segment<'data, 'file> {
    fn address(&self) -> u64 {
        with_inner!(self.inner, SegmentInternal, |x| x.address())
    }

    fn size(&self) -> u64 {
        with_inner!(self.inner, SegmentInternal, |x| x.size())
    }

    fn data(&self) -> &'data [u8] {
        with_inner!(self.inner, SegmentInternal, |x| x.data())
    }

    fn name(&self) -> Option<&str> {
        with_inner!(self.inner, SegmentInternal, |x| x.name())
    }
}

impl<'data, 'file> Iterator for SectionIterator<'data, 'file> {
    type Item = Section<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        next_inner!(self.inner, SectionIteratorInternal, SectionInternal)
            .map(|inner| Section { inner })
    }
}

impl<'data, 'file> fmt::Debug for Section<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("Section")
            .field("name", &self.name().unwrap_or("<invalid name>"))
            .field("address", &self.address())
            .field("size", &self.data().len())
            .field("kind", &self.kind())
            .finish()
    }
}

impl<'data, 'file> ObjectSection<'data> for Section<'data, 'file> {
    fn address(&self) -> u64 {
        with_inner!(self.inner, SectionInternal, |x| x.address())
    }

    fn size(&self) -> u64 {
        with_inner!(self.inner, SectionInternal, |x| x.size())
    }

    fn data(&self) -> &'data [u8] {
        with_inner!(self.inner, SectionInternal, |x| x.data())
    }

    fn name(&self) -> Option<&str> {
        with_inner!(self.inner, SectionInternal, |x| x.name())
    }

    fn segment_name(&self) -> Option<&str> {
        with_inner!(self.inner, SectionInternal, |x| x.segment_name())
    }

    fn kind(&self) -> SectionKind {
        with_inner!(self.inner, SectionInternal, |x| x.kind())
    }
}

impl<'data, 'file> Iterator for SymbolIterator<'data, 'file> {
    type Item = Symbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        with_inner_mut!(self.inner, SymbolIteratorInternal, |x| {
            x.next()
        })
    }
}

impl<'data> Symbol<'data> {
    /// Return the kind of this symbol.
    #[inline]
    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Returns the section kind for the symbol, or `None` if the symbol is undefined.
    #[inline]
    pub fn section_kind(&self) -> Option<SectionKind> {
        self.section_kind
    }

    /// Return true if the symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.section_kind.is_none()
    }

    /// Return true if the symbol is global.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Return true if the symbol is local.
    #[inline]
    pub fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// The name of the symbol.
    #[inline]
    pub fn name(&self) -> Option<&'data str> {
        self.name
    }

    /// The address of the symbol. May be zero if the address is unknown.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The size of the symbol. May be zero if the size is unknown.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The index of the object file that this symbol came from.
    ///
    /// This is only useful in conjunction with `SymbolMap::object_file`.
    pub fn object_file_index(&self) -> Option<usize> {
        self.object_file_index.get()
    }

}

impl SymbolObjectFileIndex {
    fn get(self) -> Option<usize> {
        if self == Self::default() {
            None
        } else {
            Some(self.0)
        }
    }
}

impl Default for SymbolObjectFileIndex {
    fn default() -> Self {
        SymbolObjectFileIndex(std::usize::MAX)
    }
}

impl<'data> SymbolMap<'data> {
    /// Get the symbol containing the given address.
    pub fn get(&self, address: u64) -> Option<&Symbol<'data>> {
        self.symbols
            .binary_search_by(|symbol| {
                if address < symbol.address {
                    std::cmp::Ordering::Greater
                } else if address < symbol.address + symbol.size {
                    std::cmp::Ordering::Equal
                } else {
                    std::cmp::Ordering::Less
                }
            })
            .ok()
            .and_then(|index| self.symbols.get(index))
    }

    /// Get the source object file for a symbol.
    pub fn object_file(&self, index: usize) -> Option<&SymbolObjectFile<'data>> {
        self.object_files.get(index)
    }

    /// The number of object files in the map.
    pub fn object_file_count(&self) -> usize {
        self.object_files.len()
    }

    /// Get all symbols in the map.
    pub fn symbols(&self) -> &[Symbol<'data>] {
        &self.symbols
    }

    /// Return true for symbols that should be included in the map.
    fn filter(symbol: &Symbol) -> bool {
        match symbol.kind() {
            SymbolKind::Unknown | SymbolKind::Text | SymbolKind::Data => {}
            SymbolKind::Section | SymbolKind::File | SymbolKind::Common | SymbolKind::Tls => {
                return false
            }
        }
        !symbol.is_undefined() && symbol.size() > 0
    }
}
