use std::io::{self, ErrorKind, Read};

/// Reads `reader` to its end, or `None` when it holds more than `limit` bytes.
pub(crate) fn read_limited(reader: impl Read, limit: u64) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(read).map_or(true, |read| read > limit) {
        return Ok(None);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}
