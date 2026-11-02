//! Just enough ZIP to read a Pi-hole Teleporter archive: the central directory,
//! stored and deflated entries. No ZIP64, no encryption, no multi-disk — a
//! Teleporter archive is a few small files, and anything else is refused with
//! a reason rather than half-read.

use std::io::Read;

/// The largest entry we will inflate. Teleporter's own importer stops at
/// 256 MiB; the files it holds are a few MiB at most.
const MAX_ENTRY: u64 = 64 * 1024 * 1024;

pub struct Entry {
    pub name: String,
    method: u16,
    compressed: u64,
    uncompressed: u64,
    local_offset: u64,
}

/// The entries of the archive in `data`, from its central directory.
pub fn entries(data: &[u8]) -> Result<Vec<Entry>, String> {
    // End of central directory: the last `PK\x05\x06`, within the last 64 KiB
    // (its trailing comment can be that long).
    let tail_from = data.len().saturating_sub(22 + 0xFFFF);
    let eocd = (tail_from..data.len().saturating_sub(21))
        .rev()
        .find(|&i| data[i..].starts_with(b"PK\x05\x06"))
        .ok_or("not a ZIP archive")?;
    let count = u16_at(data, eocd + 10)? as usize;
    let cd_offset = u32_at(data, eocd + 16)? as usize;
    if count == 0xFFFF || cd_offset == 0xFFFF_FFFF {
        return Err("ZIP64 archives aren't supported".into());
    }

    let mut out = Vec::with_capacity(count);
    let mut at = cd_offset;
    for _ in 0..count {
        if !data.get(at..).is_some_and(|d| d.starts_with(b"PK\x01\x02")) {
            return Err("the archive's directory is damaged".into());
        }
        let flags = u16_at(data, at + 8)?;
        if flags & 1 != 0 {
            return Err("encrypted archives aren't supported".into());
        }
        let name_len = u16_at(data, at + 28)? as usize;
        let extra_len = u16_at(data, at + 30)? as usize;
        let comment_len = u16_at(data, at + 32)? as usize;
        let name = data
            .get(at + 46..at + 46 + name_len)
            .ok_or("the archive's directory is damaged")?;
        out.push(Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            method: u16_at(data, at + 10)?,
            compressed: u64::from(u32_at(data, at + 20)?),
            uncompressed: u64::from(u32_at(data, at + 24)?),
            local_offset: u64::from(u32_at(data, at + 42)?),
        });
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// The contents of `entry`.
pub fn read(data: &[u8], entry: &Entry) -> Result<Vec<u8>, String> {
    if entry.uncompressed > MAX_ENTRY {
        return Err(format!("{} is too large to import", entry.name));
    }
    let local = entry.local_offset as usize;
    if !data
        .get(local..)
        .is_some_and(|d| d.starts_with(b"PK\x03\x04"))
    {
        return Err(format!("{} is damaged in the archive", entry.name));
    }
    let name_len = u16_at(data, local + 26)? as usize;
    let extra_len = u16_at(data, local + 28)? as usize;
    let start = local + 30 + name_len + extra_len;
    let raw = data
        .get(start..start + entry.compressed as usize)
        .ok_or_else(|| format!("{} is cut short in the archive", entry.name))?;
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => {
            let mut out = Vec::with_capacity(entry.uncompressed as usize);
            flate2::read::DeflateDecoder::new(raw)
                .take(MAX_ENTRY + 1)
                .read_to_end(&mut out)
                .map_err(|e| format!("{} won't decompress: {e}", entry.name))?;
            if out.len() as u64 > MAX_ENTRY {
                return Err(format!("{} is too large to import", entry.name));
            }
            Ok(out)
        }
        m => Err(format!("{} uses compression method {m}", entry.name)),
    }
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "the archive is cut short".into())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "the archive is cut short".into())
}

/// A ZIP of `files`, deflated — for tests that need a Teleporter archive.
#[cfg(test)]
pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, body) in files {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(body).unwrap();
        let packed = enc.finish().unwrap();
        let crc = crc32(body);
        let offset = out.len() as u32;
        let header = |sig: &[u8], central: bool| {
            let mut h = Vec::new();
            h.extend_from_slice(sig);
            if central {
                h.extend_from_slice(&20u16.to_le_bytes()); // made by
            }
            h.extend_from_slice(&20u16.to_le_bytes()); // needed
            h.extend_from_slice(&0u16.to_le_bytes()); // flags
            h.extend_from_slice(&8u16.to_le_bytes()); // deflate
            h.extend_from_slice(&[0, 0, 0, 0]); // time, date
            h.extend_from_slice(&crc.to_le_bytes());
            h.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central {
                h.extend_from_slice(&[0; 6]); // comment, disk, internal attrs
                h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
                h.extend_from_slice(&offset.to_le_bytes());
            }
            h.extend_from_slice(name.as_bytes());
            h
        };
        out.extend(header(b"PK\x03\x04", false));
        out.extend(&packed);
        central.extend(header(b"PK\x01\x02", true));
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend(central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_what_it_built() {
        let zip = build(&[("a.txt", b"hello hello hello"), ("dir/b.bin", &[7u8; 5000])]);
        let list = entries(&zip).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].name, "dir/b.bin");
        assert_eq!(read(&zip, &list[0]).unwrap(), b"hello hello hello");
        assert_eq!(read(&zip, &list[1]).unwrap(), vec![7u8; 5000]);
        assert!(entries(b"not a zip at all").is_err());
    }
}
