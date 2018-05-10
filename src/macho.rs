use std::fmt;
use std::slice;
use alloc::vec::Vec;

use goblin::mach;
use goblin::mach::load_command::CommandVariant;
use uuid::Uuid;

use {DebugFileInfo, Machine, Object, ObjectSection, ObjectSegment, SectionKind, Symbol, SymbolKind,
     SymbolMap, SymbolObjectFile, SymbolObjectFileIndex };

/// A Mach-O object file.
#[derive(Debug)]
pub struct MachOFile<'data> {
    macho: mach::MachO<'data>,
}

/// An iterator over the segments of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    segments: slice::Iter<'file, mach::segment::Segment<'data>>,
}

/// A segment of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegment<'data, 'file>
where
    'data: 'file,
{
    segment: &'file mach::segment::Segment<'data>,
}

/// An iterator over the sections of a `MachOFile`.
pub struct MachOSectionIterator<'data, 'file>
where
    'data: 'file,
{
    segments: slice::Iter<'file, mach::segment::Segment<'data>>,
    sections: Option<mach::segment::SectionIterator<'data>>,
}

/// A section of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSection<'data> {
    section: mach::segment::Section,
    data: mach::segment::SectionData<'data>,
}

/// An iterator over the symbols of a `MachOFile`.
pub struct MachOSymbolIterator<'data> {
    symbols: mach::symbols::SymbolIterator<'data>,
    section_kinds: Vec<SectionKind>,
    debug: bool,
    current_symbol_name: Option<&'data str>,
    current_symbol_address: u64,
    current_object_index: SymbolObjectFileIndex,
    max_object_index: usize,
}

impl<'data> MachOFile<'data> {
    /// Get the Mach-O headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn macho(&self) -> &mach::MachO<'data> {
        &self.macho
    }

    /// Parse the raw Mach-O file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let macho = mach::MachO::parse(data, 0).map_err(|_| "Could not parse Mach-O header")?;
        Ok(MachOFile { macho })
    }

    fn symbols(&self, debug: bool) -> MachOSymbolIterator<'data> {
        let symbols = match self.macho.symbols {
            Some(ref symbols) => symbols.into_iter(),
            None => mach::symbols::SymbolIterator::default(),
        };

        let mut section_kinds = Vec::new();
        // Don't use MachOSectionIterator because it skips sections it fails to parse,
        // and the section index is important.
        for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, data)) = section {
                    let section = MachOSection { section, data };
                    section_kinds.push(section.kind());
                } else {
                    // Add placeholder so that indexing works.
                    section_kinds.push(SectionKind::Unknown);
                }
            }
        }

        MachOSymbolIterator {
            symbols,
            section_kinds,
            debug,
            current_symbol_name: None,
            current_symbol_address: 0,
            current_object_index: Default::default(),
            max_object_index: 0,
        }
    }
}

impl<'data, 'file> Object<'data, 'file> for MachOFile<'data>
where
    'data: 'file,
{
    type Segment = MachOSegment<'data, 'file>;
    type SegmentIterator = MachOSegmentIterator<'data, 'file>;
    type Section = MachOSection<'data>;
    type SectionIterator = MachOSectionIterator<'data, 'file>;
    type SymbolIterator = MachOSymbolIterator<'data>;

    fn machine(&self) -> Machine {
        match self.macho.header.cputype {
            mach::cputype::CPU_TYPE_ARM => Machine::Arm,
            mach::cputype::CPU_TYPE_ARM64 => Machine::Arm64,
            mach::cputype::CPU_TYPE_X86 => Machine::X86,
            mach::cputype::CPU_TYPE_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'file self) -> MachOSegmentIterator<'data, 'file> {
        MachOSegmentIterator {
            segments: self.macho.segments.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]> {
        // Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
        // ".debug_info" to "__debug_info".
        let (system_section, section_name) = if section_name.starts_with('.') {
            (true, &section_name[1..])
        } else {
            (false, section_name)
        };
        let cmp_section_name = |name: &str| if system_section {
            name.starts_with("__") && section_name == &name[2..]
        } else {
            section_name == name
        };

        for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, data)) = section {
                    if let Ok(name) = section.name() {
                        if cmp_section_name(name) {
                            return Some(data);
                        }
                    }
                }
            }
        }
        None
    }

    fn sections(&'file self) -> MachOSectionIterator<'data, 'file> {
        MachOSectionIterator {
            segments: self.macho.segments.iter(),
            sections: None,
        }
    }

    fn symbols(&'file self) -> MachOSymbolIterator<'data> {
        MachOFile::symbols(self, true)
    }

    fn dynamic_symbols(&'file self) -> MachOSymbolIterator<'data> {
        // The LC_DYSYMTAB command contains indices into the same symbol
        // table as the LC_SYMTAB command, so return all of them except
        // the debugging symbols.
        MachOFile::symbols(self, false)
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut object_files = Vec::new();
        if let Some(ref symbols) = self.macho.symbols {
            for symbol in symbols {
                if let Ok((name, nlist)) = symbol {
                    if nlist.n_type == mach::symbols::N_OSO {
                        object_files.push(SymbolObjectFile {
                            path: name,
                            timestamp: nlist.n_value,
                        });
                    }
                }
            }
        }

        let mut symbols: Vec<_> = MachOFile::symbols(self, true).collect();

        // Add symbols for the end of each section.
        for section in self.sections() {
            symbols.push(Symbol {
                name: None,
                address: section.address() + section.size(),
                size: 0,
                kind: SymbolKind::Section,
                section_kind: None,
                global: false,
                object_file_index: Default::default(),
            });
        }

        // Calculate symbol sizes by sorting and finding the next symbol.
        symbols.sort_by(|a, b| {
            a.address.cmp(&b.address).then_with(|| {
                // Place the end of section symbols last.
                (a.kind == SymbolKind::Section).cmp(&(b.kind == SymbolKind::Section))
            }).then_with(|| a.size.cmp(&b.size))
        });

        for i in 0..symbols.len() {
            let (before, after) = symbols.split_at_mut(i + 1);
            let symbol = &mut before[i];
            // Only N_STAB symbols have a size, so guess the size for others.
            if symbol.size == 0 && symbol.kind != SymbolKind::Section {
                for next in after.iter() {
                    if next.address != symbol.address {
                        symbol.size = next.address - symbol.address;
                        break;
                    }
                    if next.size != 0 {
                        // There's a STAB symbol with a size at the same address,
                        // so the map can return that instead.
                        break;
                    }
                    if next.kind == SymbolKind::Section {
                        // This probably shouldn't happen, but just in case.
                        break;
                    }
                }
            }
        }

        symbols.retain(SymbolMap::filter);
        SymbolMap { symbols, object_files }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.macho.little_endian
    }

    fn has_debug_symbols(&self) -> bool {
        self.section_data_by_name(".debug_info").is_some()
    }

    fn debug_file_info(&self) -> Option<DebugFileInfo> {
        // Return the UUID from the `LC_UUID` load command, if one is present.
        self.macho.load_commands.iter().filter_map(|lc| {
            match lc.command {
                CommandVariant::Uuid(ref cmd) => {
                    //TODO: Uuid should have a `from_array` method that can't fail.
                    Uuid::from_bytes(&cmd.uuid).ok()
                        .map(|uuid| DebugFileInfo::MachOUuid(uuid))
                }
                _ => None,
            }
        }).nth(0)
    }

    fn entry(&self) -> u64 {
        self.macho.entry
    }
}

impl<'data, 'file> Iterator for MachOSegmentIterator<'data, 'file> {
    type Item = MachOSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.segments.next().map(|segment| MachOSegment { segment })
    }
}

impl<'data, 'file> ObjectSegment<'data> for MachOSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.vmaddr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.vmsize
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.segment.data
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.segment.name().ok()
    }
}

impl<'data, 'file> fmt::Debug for MachOSectionIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("MachOSectionIterator").finish()
    }
}

impl<'data, 'file> Iterator for MachOSectionIterator<'data, 'file> {
    type Item = MachOSection<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut sections) = self.sections {
                while let Some(section) = sections.next() {
                    if let Ok((section, data)) = section {
                        return Some(MachOSection { section, data });
                    }
                }
            }
            match self.segments.next() {
                None => return None,
                Some(segment) => {
                    self.sections = Some(segment.into_iter());
                }
            }
        }
    }
}

impl<'data> ObjectSection<'data> for MachOSection<'data> {
    #[inline]
    fn address(&self) -> u64 {
        self.section.addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.size
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.data
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name().ok()
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        self.section.segname().ok()
    }

    fn kind(&self) -> SectionKind {
        match (self.segment_name(), self.name()) {
            (Some("__TEXT"), Some("__text")) => SectionKind::Text,
            (Some("__DATA"), Some("__data")) => SectionKind::Data,
            (Some("__DATA"), Some("__bss")) => SectionKind::UninitializedData,
            _ => SectionKind::Other,
        }
    }
}

impl<'data> fmt::Debug for MachOSymbolIterator<'data> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MachOSymbolIterator").finish()
    }
}

impl<'data> MachOSymbolIterator<'data> {
    fn next_stab_symbol(&mut self, name: &'data str, nlist: &mach::symbols::Nlist) -> Option<Symbol<'data>> {
        debug_assert!(nlist.n_type & mach::symbols::N_STAB != 0);

        match nlist.n_type {
            // TODO: there's probably more symbols that could be returned, but they're not
            // currently needed.
            mach::symbols::N_FUN => {
                if name.len() == 0 {
                    if let Some(name) = self.current_symbol_name {
                        return Some(Symbol {
                            name: Some(name),
                            address: self.current_symbol_address,
                            size: nlist.n_value,
                            kind: SymbolKind::Text,
                            section_kind: Some(SectionKind::Text),
                            // `None` would be better here.
                            global: false,
                            object_file_index: self.current_object_index,
                        });
                    }
                } else {
                    self.current_symbol_name = Some(name);
                    self.current_symbol_address = nlist.n_value;
                }
            }
            mach::symbols::N_OSO => {
                self.current_object_index = SymbolObjectFileIndex(self.max_object_index);
                self.max_object_index += 1;
            }
            mach::symbols::N_SO => {
                self.current_object_index = Default::default();
            }
            _ => {}
        }
        None
    }

    fn next_symbol(&mut self, name: &'data str, nlist: &mach::symbols::Nlist) -> Option<Symbol<'data>> {
        debug_assert!(nlist.n_type & mach::symbols::N_STAB == 0);

        let n_type = nlist.n_type & mach::symbols::NLIST_TYPE_MASK;
        let section_kind = if n_type == mach::symbols::N_SECT {
            if nlist.n_sect == 0 {
                None
            } else {
                self.section_kinds.get(nlist.n_sect - 1).cloned()
            }
        } else {
            // TODO: better handling for other n_type values
            None
        };
        let kind = match section_kind {
            Some(SectionKind::Text) => SymbolKind::Text,
            Some(SectionKind::Data)
                | Some(SectionKind::ReadOnlyData)
                | Some(SectionKind::UninitializedData) => SymbolKind::Data,
            _ => SymbolKind::Unknown,
        };
        Some(Symbol {
            name: Some(name),
            address: nlist.n_value,
            // Only calculated for symbol maps
            size: 0,
            kind,
            section_kind,
            global: nlist.is_global(),
            object_file_index: Default::default(),
        })
    }
}

impl<'data> Iterator for MachOSymbolIterator<'data> {
    type Item = Symbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(symbol) = self.symbols.next() {
            if let Ok((name, nlist)) = symbol {
                let result = if nlist.n_type & mach::symbols::N_STAB != 0 {
                    if self.debug {
                        self.next_stab_symbol(name, &nlist)
                    } else {
                        None
                    }
                } else {
                    self.next_symbol(name, &nlist)
                };
                if result.is_some() {
                    return result;
                }
            }
        }
        None
    }
}
