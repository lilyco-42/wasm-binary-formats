//! Bounds-checked little-endian reader shared by the header parsers.
//!
//! Every accessor returns `None` rather than panicking: the buffers handed to this crate come
//! from an uploaded file, so a truncated or lied-about offset has to be a parse failure, never
//! an out-of-bounds read.

pub struct Le<'a>(pub &'a [u8]);

impl Le<'_> {
    pub fn at(&self, offset: usize) -> Option<Self> {
        if offset <= self.0.len() {
            Some(Self(&self.0[offset..]))
        } else {
            None
        }
    }

    pub fn u16(&self, offset: usize) -> Option<i32> {
        let end = offset.checked_add(2)?;
        if end > self.0.len() {
            return None;
        }
        Some(i32::from(u16::from_le_bytes(
            self.0[offset..end].try_into().unwrap(),
        )))
    }

    pub fn u32(&self, offset: usize) -> Option<i64> {
        let end = offset.checked_add(4)?;
        if end > self.0.len() {
            return None;
        }
        Some(i64::from(u32::from_le_bytes(
            self.0[offset..end].try_into().unwrap(),
        )))
    }

    pub fn u64(&self, offset: usize) -> Option<i64> {
        let end = offset.checked_add(8)?;
        if end > self.0.len() {
            return None;
        }
        Some(u64::from_le_bytes(self.0[offset..end].try_into().unwrap()) as i64)
    }

    pub fn bytes(&self, offset: usize, len: usize) -> Option<&'a [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.0.len() {
            return None;
        }
        Some(&self.0[offset..end])
    }
}

pub fn utf8_or_hex(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || c == '\t' || c == '\n') =>
        {
            text.to_string()
        }
        _ => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}
