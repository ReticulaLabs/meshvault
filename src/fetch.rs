//! Piece-range scheduling for multi-source fetching.
//!
//! Several workers (one per peer) share a [`PieceProgress`].  A worker claims
//! a contiguous range of not-yet-verified, not-yet-claimed pieces, downloads
//! it, and marks it complete.  Claimed ranges never overlap, so writes to the
//! partial file are disjoint and can be performed concurrently.

/// Tracks verified and in-flight piece ranges.
pub struct PieceProgress {
    verified: Vec<bool>,
    claimed: Vec<bool>,
    remaining: usize,
    cursor: usize,
}

impl PieceProgress {
    pub fn new(verified: Vec<bool>) -> Self {
        let remaining = verified.iter().filter(|done| !**done).count();
        let claimed = vec![false; verified.len()];
        Self {
            verified,
            claimed,
            remaining,
            cursor: 0,
        }
    }

    pub fn total(&self) -> usize {
        self.verified.len()
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    pub fn verified_count(&self) -> usize {
        self.verified.len() - self.remaining
    }

    pub fn all_done(&self) -> bool {
        self.remaining == 0
    }

    pub fn is_verified(&self, index: u32) -> bool {
        self.verified.get(index as usize).copied().unwrap_or(false)
    }

    /// Claim up to `requested` contiguous pieces.  Returns `(start, count)`.
    pub fn claim(&mut self, requested: u32) -> Option<(u32, u32)> {
        if self.remaining == 0 || self.verified.is_empty() {
            return None;
        }
        let len = self.verified.len();
        let limit = requested.max(1) as usize;

        let mut start = None;
        for offset in 0..len {
            let index = (self.cursor + offset) % len;
            if !self.verified[index] && !self.claimed[index] {
                start = Some(index);
                break;
            }
        }
        let start = start?;

        let mut count = 0usize;
        while count < limit
            && start + count < len
            && !self.verified[start + count]
            && !self.claimed[start + count]
        {
            count += 1;
        }
        if count == 0 {
            return None;
        }
        for index in start..start + count {
            self.claimed[index] = true;
        }
        self.cursor = (start + count) % len;
        Some((start as u32, count as u32))
    }

    /// Mark a claimed range as verified.  Idempotent.
    pub fn complete(&mut self, start: u32, count: u32) {
        let start = start as usize;
        let end = (start + count as usize).min(self.verified.len());
        for index in start..end {
            if !self.verified[index] {
                self.verified[index] = true;
                self.remaining = self.remaining.saturating_sub(1);
            }
            self.claimed[index] = false;
        }
        self.cursor = start.min(self.cursor);
    }

    /// Return a claimed range to the pool after a failed download.
    pub fn release(&mut self, start: u32, count: u32) {
        let start = start as usize;
        let end = (start + count as usize).min(self.claimed.len());
        for index in start..end {
            self.claimed[index] = false;
        }
        self.cursor = start.min(self.cursor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_do_not_overlap() {
        let mut progress = PieceProgress::new(vec![false; 10]);
        assert_eq!(progress.claim(3), Some((0, 3)));
        assert_eq!(progress.claim(3), Some((3, 3)));
        assert_eq!(progress.claim(3), Some((6, 3)));
        assert_eq!(progress.claim(3), Some((9, 1)));
        assert_eq!(progress.claim(3), None);
    }

    #[test]
    fn verified_pieces_are_skipped() {
        let mut progress = PieceProgress::new(vec![false, true, false, false, true]);
        assert_eq!(progress.claim(4), Some((0, 1)));
        assert_eq!(progress.claim(4), Some((2, 2)));
        assert_eq!(progress.claim(1), None);
    }

    #[test]
    fn release_allows_reclaim() {
        let mut progress = PieceProgress::new(vec![false; 4]);
        let (start, count) = progress.claim(2).unwrap();
        progress.release(start, count);
        assert_eq!(progress.claim(2), Some((0, 2)));
    }

    #[test]
    fn completion_updates_counts() {
        let mut progress = PieceProgress::new(vec![false; 5]);
        let (start, count) = progress.claim(3).unwrap();
        progress.complete(start, count);
        assert_eq!(progress.verified_count(), 3);
        assert_eq!(progress.remaining(), 2);
        assert!(!progress.all_done());
        let (start, count) = progress.claim(5).unwrap();
        progress.complete(start, count);
        assert!(progress.all_done());
    }

    #[test]
    fn empty_file_is_done() {
        let progress = PieceProgress::new(Vec::new());
        assert!(progress.all_done());
        assert_eq!(progress.remaining(), 0);
    }

    #[test]
    fn claims_stop_at_contiguous_hole() {
        let mut progress = PieceProgress::new(vec![false, true, false, false]);
        assert_eq!(progress.claim(10), Some((0, 1)));
        assert_eq!(progress.claim(10), Some((2, 2)));
    }
}
