//! The domains of one list, held as a buffer plus an index instead of a
//! `Vec<String>`.
//!
//! A million-domain subscription is a million separate heap allocations that
//! way: ~56 MB to hold ~30 MB of text, and a million pieces for the allocator to
//! keep track of (and to hold on to afterwards). Here it is two allocations —
//! the domains end to end, and one span each — which is where a refresh's peak
//! now sits on a box whose whole memory target is a few tens of megabytes.

/// One list's domains: the text of all of them, and where each one lies in it.
///
/// The text is held in fixed-size chunks that are never reallocated. One
/// growing buffer would be simpler, but a `String` grows by doubling: at 30 MB
/// of domains it would ask for 64 MB and copy the lot — a worse peak than the
/// million little allocations this type exists to replace.
///
/// Two sets are equal when they hold the same domains in the same order —
/// whatever the buffer behind them looks like, since a removed or shortened
/// span leaves its bytes in place.
#[derive(Debug)]
pub struct DomainSet {
    chunks: Vec<String>,
    /// How many bytes each chunk addresses. A span's offset is virtual across
    /// all chunks, so `offset / chunk_bytes` picks the chunk it lands in; a
    /// domain never straddles two.
    chunk_bytes: usize,
    /// `(start, end)` of each domain, in the order they were added.
    spans: Vec<(u32, u32)>,
}

/// Size of one text chunk. Big enough that the per-chunk tail waste is
/// irrelevant, small enough to not matter if a list ends just past a boundary.
const CHUNK_BYTES: usize = 4 << 20;

/// Longest text a single set can hold — spans are 32-bit, and a list this size
/// is far beyond anything real.
const MAX_TEXT_BYTES: usize = u32::MAX as usize;

impl Default for DomainSet {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            chunk_bytes: CHUNK_BYTES,
            spans: Vec::new(),
        }
    }
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a set over text that is already a list of domains, one per line —
    /// the on-disk domain cache. The text becomes the set's single chunk as it
    /// stands, so this costs the spans and nothing else.
    pub fn from_lines(text: String) -> Self {
        let mut spans = Vec::new();
        let mut offset = 0usize;
        for line in text.split('\n') {
            let start = offset;
            offset += line.len() + 1; // the separator that split consumed
            let line = line.strip_suffix('\r').unwrap_or(line);
            if !line.is_empty() && start + line.len() <= MAX_TEXT_BYTES {
                spans.push((start as u32, (start + line.len()) as u32));
            }
        }
        Self {
            chunk_bytes: text.len().max(1),
            chunks: vec![text],
            spans,
        }
    }

    /// Append `domain` lowercased, keeping it only if `accept` takes the
    /// lowercased form. Nothing is allocated for the candidate itself: it is
    /// written into the current chunk and rolled back when rejected.
    pub fn push_lowercase_if(&mut self, domain: &str, accept: impl FnOnce(&str) -> bool) -> bool {
        if domain.is_empty() || domain.len() > self.chunk_bytes {
            return false;
        }
        // Start a new chunk rather than let a domain straddle two.
        let room = self
            .chunks
            .last()
            .is_some_and(|c| c.len() + domain.len() <= self.chunk_bytes);
        if !room {
            if (self.chunks.len() + 1) * self.chunk_bytes > MAX_TEXT_BYTES {
                return false;
            }
            self.chunks.push(String::with_capacity(self.chunk_bytes));
        }
        let chunk_index = self.chunks.len() - 1;
        let chunk = &mut self.chunks[chunk_index];
        let start = chunk.len();
        chunk.push_str(domain);
        chunk[start..].make_ascii_lowercase();
        if !accept(&chunk[start..]) {
            chunk.truncate(start);
            return false;
        }
        let base = chunk_index * self.chunk_bytes;
        self.spans
            .push(((base + start) as u32, (base + chunk.len()) as u32));
        true
    }

    /// Append an already-normalised domain.
    pub fn push(&mut self, domain: &str) {
        self.push_lowercase_if(domain, |_| true);
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    fn slice(&self, span: (u32, u32)) -> &str {
        let start = span.0 as usize;
        let chunk = &self.chunks[start / self.chunk_bytes];
        let offset = start % self.chunk_bytes;
        &chunk[offset..offset + (span.1 - span.0) as usize]
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.spans.iter().map(|span| self.slice(*span))
    }

    /// Drop every domain `keep` rejects. The text stays as it is — the removed
    /// spans simply stop pointing at it — so this costs no copy.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        let chunks = &self.chunks;
        let chunk_bytes = self.chunk_bytes;
        self.spans.retain(|span| {
            let start = span.0 as usize;
            let chunk = &chunks[start / chunk_bytes];
            let offset = start % chunk_bytes;
            keep(&chunk[offset..offset + (span.1 - span.0) as usize])
        });
    }

    /// Put the domains in the strictly increasing order an FST demands: strip
    /// the trailing root dot that FQDN-form entries carry (`ads.example.com.`),
    /// then sort and drop duplicates. Trailing dots are cut by moving the span,
    /// never the text.
    pub fn prepare_keys(&mut self) {
        let chunks = &self.chunks;
        let chunk_bytes = self.chunk_bytes;
        let at = |span: &(u32, u32)| -> &str {
            let start = span.0 as usize;
            let chunk = &chunks[start / chunk_bytes];
            let offset = start % chunk_bytes;
            &chunk[offset..offset + (span.1 - span.0) as usize]
        };
        for span in self.spans.iter_mut() {
            while span.1 > span.0 {
                let start = span.0 as usize;
                let chunk = chunks[start / chunk_bytes].as_bytes();
                let last = start % chunk_bytes + (span.1 - span.0) as usize - 1;
                if chunk[last] != b'.' {
                    break;
                }
                span.1 -= 1;
            }
        }
        self.spans.sort_unstable_by(|a, b| at(a).cmp(at(b)));
        self.spans.dedup_by(|a, b| at(a) == at(b));
    }

    /// The domains as owned strings — for tests and the few callers that want a
    /// plain list. Allocates the very thing this type exists to avoid, so it is
    /// never on the refresh path.
    pub fn to_vec(&self) -> Vec<String> {
        self.iter().map(String::from).collect()
    }
}

impl PartialEq for DomainSet {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for DomainSet {}

impl From<Vec<String>> for DomainSet {
    fn from(domains: Vec<String>) -> Self {
        domains.into_iter().collect()
    }
}

impl FromIterator<String> for DomainSet {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let mut set = Self::new();
        for domain in iter {
            set.push(&domain);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_what_is_accepted_and_rolls_back_the_rest() {
        let mut set = DomainSet::new();
        assert!(set.push_lowercase_if("Ads.Example.COM", |d| d.contains('.')));
        assert!(!set.push_lowercase_if("localhost", |d| d.contains('.')));
        assert!(set.push_lowercase_if("tracker.example.net", |d| d.contains('.')));

        assert_eq!(set.len(), 2);
        assert_eq!(
            set.to_vec(),
            vec!["ads.example.com", "tracker.example.net"],
            "a rejected candidate must leave no trace in the buffer"
        );
    }

    #[test]
    fn prepare_keys_sorts_dedups_and_cuts_root_dots() {
        let mut set: DomainSet = ["b.test.", "a.test", "b.test", "a.test..", "c.test"]
            .iter()
            .map(|d| d.to_string())
            .collect();
        set.prepare_keys();
        assert_eq!(set.to_vec(), vec!["a.test", "b.test", "c.test"]);
    }

    #[test]
    fn retain_drops_spans_without_touching_the_text() {
        let mut set: DomainSet = ["keep.test", "drop.test", "keep2.test"]
            .iter()
            .map(|d| d.to_string())
            .collect();
        set.retain(|d| !d.starts_with("drop"));
        assert_eq!(set.to_vec(), vec!["keep.test", "keep2.test"]);
    }

    /// A set larger than one chunk has to read back exactly the same, with no
    /// domain straddling a boundary and no span pointing at the wrong chunk.
    #[test]
    fn spans_survive_chunk_boundaries() {
        let mut set = DomainSet::new();
        // Enough to fill several chunks.
        let expected: Vec<String> = (0..400_000)
            .map(|i| format!("host{i}.chunked.example.com"))
            .collect();
        for domain in &expected {
            set.push(domain);
        }
        assert!(set.chunks.len() > 2, "test must span several chunks");
        assert_eq!(set.len(), expected.len());
        assert_eq!(set.to_vec(), expected);

        // And sorting across chunks still yields a strictly increasing set.
        set.prepare_keys();
        let sorted = set.to_vec();
        let mut want = expected.clone();
        want.sort();
        want.dedup();
        assert_eq!(sorted, want);
    }

    #[test]
    fn from_lines_reads_a_domain_cache_as_it_lies() {
        let set = DomainSet::from_lines("a.test\nb.test\r\n\nc.test".to_string());
        assert_eq!(set.to_vec(), vec!["a.test", "b.test", "c.test"]);
        assert!(DomainSet::from_lines(String::new()).is_empty());
    }
}
