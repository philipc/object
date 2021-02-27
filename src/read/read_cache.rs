use std::boxed::Box;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{Read, Seek, SeekFrom};
use std::mem;

use crate::read::ReadRef;

/// TODO
#[derive(Debug)]
pub struct ReadCache<R: Read + Seek> {
    cache: RefCell<ReadCacheInternal<R>>,
}

#[derive(Debug)]
struct ReadCacheInternal<R: Read + Seek> {
    read: R,
    bufs: HashMap<(u64, u64), Box<[u8]>>,
}

/// TODO
impl<R: Read + Seek> ReadCache<R> {
    /// TODO
    pub fn new(read: R) -> Self {
        ReadCache {
            cache: RefCell::new(ReadCacheInternal {
                read,
                bufs: HashMap::new(),
            }),
        }
    }

    /// TODO
    pub fn range<'data>(&'data self, offset: u64, size: u64) -> ReadCacheRange<'data, R> {
        ReadCacheRange {
            r: self,
            offset,
            size,
        }
    }
}

impl<'data, R: Read + Seek> ReadRef<'data> for &'data ReadCache<R> {
    fn len(self) -> Result<u64, ()> {
        let cache = &mut *self.cache.borrow_mut();
        cache.read.seek(SeekFrom::End(0)).map_err(|_| ())
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'data [u8], ()> {
        if size == 0 {
            return Ok(&[]);
        }
        let cache = &mut *self.cache.borrow_mut();
        let buf = match cache.bufs.entry((offset, size)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let size = size.try_into().map_err(|_| ())?;
                cache
                    .read
                    .seek(SeekFrom::Start(offset as u64))
                    .map_err(|_| ())?;
                let mut bytes = vec![0; size].into_boxed_slice();
                cache.read.read_exact(&mut bytes).map_err(|_| ())?;
                entry.insert(bytes)
            }
        };
        // Extend the lifetime to that of self.
        // This is OK because we never mutate or remove entries.
        Ok(unsafe { mem::transmute::<&[u8], &[u8]>(buf) })
    }
}

/// TODO
#[derive(Debug)]
pub struct ReadCacheRange<'data, R: Read + Seek> {
    r: &'data ReadCache<R>,
    offset: u64,
    size: u64,
}

impl<'data, R: Read + Seek> Clone for ReadCacheRange<'data, R> {
    fn clone(&self) -> Self {
        Self {
            r: self.r,
            offset: self.offset,
            size: self.size,
        }
    }
}

impl<'data, R: Read + Seek> Copy for ReadCacheRange<'data, R> {}

impl<'data, R: Read + Seek> ReadRef<'data> for ReadCacheRange<'data, R> {
    fn len(self) -> Result<u64, ()> {
        Ok(self.size)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'data [u8], ()> {
        if size == 0 {
            return Ok(&[]);
        }
        let end = offset.checked_add(size).ok_or(())?;
        if end > self.size {
            return Err(());
        }
        let r_offset = self.offset.checked_add(offset).ok_or(())?;
        self.r.read_bytes_at(r_offset, size)
    }
}
