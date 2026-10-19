/// Vanity string matching for Silent Payment addresses.

#[derive(Clone, Debug)]
pub enum MatchMode {
    /// The address must contain the pattern anywhere (case-insensitive).
    Contains,
    /// The address (after the HRP prefix "sp1" or "tsp1") must start with the pattern.
    Prefix,
    /// The address must end with the pattern.
    Suffix,
}

#[derive(Clone, Debug)]
pub struct Matcher {
    pattern:    String,   
    mode:       MatchMode,
}

/// BIP-352 v0 silent payment addresses (version 0) begin with `sp1qq…` / `tsp1qq…`.
/// Vanity patterns apply only after that fixed prefix.
#[inline]
fn vanity_search_start(address: &str) -> usize {
    let lower = address.to_ascii_lowercase();
    if lower.starts_with("tsp1qq") {
        return 6;
    }
    if lower.starts_with("sp1qq") {
        return 5;
    }
    if lower.starts_with("tsp1q") {
        return 5;
    }
    if lower.starts_with("sp1q") {
        return 4;
    }
    address
        .find('1')
        .map(|i| i + 2)
        .unwrap_or(0)
}

#[inline]
fn searchable_part(address: &str) -> &str {
    let start = vanity_search_start(address);
    address.get(start..).unwrap_or("")
}

impl Matcher {
    pub fn new(pattern: &str, mode: MatchMode) -> Self {
        Self {
            pattern: pattern.to_lowercase(),
            mode,
        }
    }

    #[inline]
    pub fn is_prefix(&self) -> bool { matches!(self.mode, MatchMode::Prefix) }

    pub fn matches(&self, address: &str) -> bool {
        let slice = searchable_part(address);
        match self.mode {
            MatchMode::Contains => slice.contains(self.pattern.as_str()),
            MatchMode::Prefix   => slice.starts_with(self.pattern.as_str()),
            MatchMode::Suffix   => address.ends_with(self.pattern.as_str()),
        }
    }

    pub fn expected_attempts(&self) -> u64 {
        let k = self.pattern.len() as u32;
        32u64.saturating_pow(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let m = Matcher::new("abc", MatchMode::Contains);
        assert!(m.matches("sp1qqqabcxyz"));
        assert!(!m.matches("sp1qqqxyzdef"));
    }

    #[test]
    fn test_contains_skips_hrp() {
        let m = Matcher::new("sp1", MatchMode::Contains);
        assert!(!m.matches("sp1qqqcafexyz"), "HRP must not be searchable");
    }

    #[test]
    fn test_prefix_skips_fixed_sp1qq() {
        let m = Matcher::new("abc", MatchMode::Prefix);
        assert!(m.matches("sp1qqabcxyz"));
        assert!(!m.matches("sp1qqqabc"));
    }

    #[test]
    fn test_suffix() {
        let m = Matcher::new("xyz", MatchMode::Suffix);
        assert!(m.matches("sp1qqqxyz"));
        assert!(!m.matches("sp1xyzqqq"));
    }

    #[test]
    fn test_case_insensitive() {
        let m = Matcher::new("ABC", MatchMode::Contains);
        assert!(m.matches("sp1qqqabcxyz"));
    }
}