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

impl Matcher {
    pub fn new(pattern: &str, mode: MatchMode) -> Self {
        Self {
            pattern: pattern.to_lowercase(),
            mode,
        }
    }

    #[inline]
    pub fn matches(&self, address: &str) -> bool {
        match self.mode {
            MatchMode::Contains => address.contains(self.pattern.as_str()),
            MatchMode::Prefix   => {
                // Skip the HRP + separator ("sp1" or "tsp1")
                let after_sep = address
                    .find('1')
                    .map(|i| &address[i + 1..])
                    .unwrap_or(address);
                after_sep.starts_with(self.pattern.as_str())
            }
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
    fn test_prefix_skips_hrp() {
        let m = Matcher::new("qqq", MatchMode::Prefix);
        // "sp1" + "qqqabc..." -> after '1': "qqqabc..."
        assert!(m.matches("sp1qqqabc"));
        assert!(!m.matches("sp1abcqqq"));
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