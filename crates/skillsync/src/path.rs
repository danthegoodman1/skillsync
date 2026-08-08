use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolPath(String);

impl ProtocolPath {
    pub fn parse(value: &str) -> Result<Self, PathError> {
        validate(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn from_utf8(bytes: &[u8]) -> Result<Self, PathError> {
        let value = std::str::from_utf8(bytes).map_err(|_| PathError::InvalidUtf8)?;
        Self::parse(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn under(&self, root: &Path) -> PathBuf {
        let mut result = root.to_path_buf();
        for component in self.0.split('/') {
            result.push(component);
        }
        result
    }
}

impl fmt::Debug for ProtocolPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProtocolPath")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ProtocolPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilenameComparison {
    CaseSensitive,
    CaseInsensitive,
}

#[derive(Debug)]
pub struct LocalPathIndex {
    comparison: FilenameComparison,
    paths: BTreeMap<String, ProtocolPath>,
}

impl LocalPathIndex {
    pub fn new(comparison: FilenameComparison) -> Self {
        Self {
            comparison,
            paths: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: ProtocolPath) -> Result<(), PathError> {
        let key = comparison_key(path.as_str(), self.comparison);
        if let Some(existing) = self.paths.get(&key)
            && existing != &path
        {
            return Err(PathError::Collision {
                first: existing.clone(),
                second: path,
            });
        }
        self.paths.insert(key, path);
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("protocol path is not valid UTF-8")]
    InvalidUtf8,
    #[error("protocol path is empty")]
    Empty,
    #[error("protocol path is absolute")]
    Absolute,
    #[error("protocol path contains a NUL byte")]
    Nul,
    #[error("protocol path contains an empty component")]
    EmptyComponent,
    #[error("protocol path contains a dot component")]
    DotComponent,
    #[error("protocol path contains a dot-dot component")]
    DotDotComponent,
    #[error("protocol paths {first:?} and {second:?} collide locally")]
    Collision {
        first: ProtocolPath,
        second: ProtocolPath,
    },
}

fn validate(value: &str) -> Result<(), PathError> {
    if value.is_empty() {
        return Err(PathError::Empty);
    }
    if value.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if value.contains('\0') {
        return Err(PathError::Nul);
    }
    for component in value.split('/') {
        match component {
            "" => return Err(PathError::EmptyComponent),
            "." => return Err(PathError::DotComponent),
            ".." => return Err(PathError::DotDotComponent),
            _ => {}
        }
    }
    Ok(())
}

fn comparison_key(value: &str, comparison: FilenameComparison) -> String {
    match comparison {
        FilenameComparison::CaseSensitive => value.to_owned(),
        FilenameComparison::CaseInsensitive => {
            value.nfd().flat_map(char::to_lowercase).collect::<String>()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_protocol_path_matrix() {
        for valid in ["SKILL.md", "skill/scripts/test.sh", r"back\\slash"] {
            assert_eq!(ProtocolPath::parse(valid).unwrap().as_str(), valid);
        }

        for (invalid, expected) in [
            ("", PathError::Empty),
            ("/absolute", PathError::Absolute),
            ("a//b", PathError::EmptyComponent),
            ("a/./b", PathError::DotComponent),
            ("a/../b", PathError::DotDotComponent),
            ("trailing/", PathError::EmptyComponent),
            ("nul\0byte", PathError::Nul),
        ] {
            assert_eq!(ProtocolPath::parse(invalid).unwrap_err(), expected);
        }
        assert_eq!(
            ProtocolPath::from_utf8(&[0xff]).unwrap_err(),
            PathError::InvalidUtf8
        );
    }

    #[test]
    fn joins_only_validated_components_under_root() {
        let path = ProtocolPath::parse("skill/scripts/check.sh").unwrap();
        assert_eq!(
            path.under(Path::new("/tmp/root")),
            PathBuf::from("/tmp/root/skill/scripts/check.sh")
        );
    }

    #[test]
    fn detects_case_and_normalization_collisions_when_required() {
        let mut index = LocalPathIndex::new(FilenameComparison::CaseInsensitive);
        index
            .insert(ProtocolPath::parse("Skill/Caf\u{e9}.md").unwrap())
            .unwrap();
        let error = index
            .insert(ProtocolPath::parse("skill/Cafe\u{301}.md").unwrap())
            .unwrap_err();
        assert!(matches!(error, PathError::Collision { .. }));

        let mut sensitive = LocalPathIndex::new(FilenameComparison::CaseSensitive);
        sensitive
            .insert(ProtocolPath::parse("Skill.md").unwrap())
            .unwrap();
        sensitive
            .insert(ProtocolPath::parse("skill.md").unwrap())
            .unwrap();
    }
}
