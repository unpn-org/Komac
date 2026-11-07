mod entry;
mod relative_location;

use std::{
    fmt,
    iter::{FilterMap, once},
    slice::Iter,
};

use compact_str::CompactString;
pub use entry::FsEntry;
use indextree::{Arena, Node, NodeId};
use itertools::{Either, Itertools};
use jiff::Timestamp;
pub use relative_location::RelativeLocation;
use typed_path::{Utf8Component, Utf8WindowsComponent, Utf8WindowsPath};

use super::{entry::DelFlags, strings::PredefinedVar};

pub struct FileSystem {
    arena: Arena<FsEntry>,
    root: NodeId,
    current_dir: NodeId,
}

impl FileSystem {
    pub fn attributes<T: AsRef<Utf8WindowsPath>>(&self, path: T) -> Option<u32> {
        let node = self
            .arena
            .get(self.get_id(path, RelativeLocation::Current)?)?;
        Some(if node.get().is_directory() { 16 } else { 128 })
    }

    /// Creates a new mock filesystem.
    pub fn new() -> Self {
        let mut arena = Arena::new();
        let root = arena.new_node(FsEntry::new_root());
        Self {
            arena,
            root,
            current_dir: root,
        }
    }

    fn parse_path<'path, T>(path: &'path T) -> impl Iterator<Item = Utf8WindowsComponent<'path>>
    where
        T: AsRef<Utf8WindowsPath> + 'path,
    {
        let path = path.as_ref();

        let components = path.components().filter(|component| {
            ![PredefinedVar::InstDir, PredefinedVar::_OutDir]
                .iter()
                .contains(component.as_str())
        });

        if path.components().next().is_some_and(|component| {
            let name = component.as_str();
            PredefinedVar::all().iter().contains(name)
                || (name.starts_with('%') && name.ends_with('%'))
        }) {
            Either::Left(once(Utf8WindowsComponent::RootDir).chain(components))
        } else {
            Either::Right(components)
        }
    }

    /// Creates a new directory from a path relative to a [location].
    /// The current directory is not changed. To both create and change the current directory, see
    /// [`set_directory`].
    ///
    /// [location]: RelativeLocation
    /// [`set_directory`]: Self::set_directory
    pub fn create_directory<T>(&mut self, name: T, location: RelativeLocation) -> NodeId
    where
        T: AsRef<Utf8WindowsPath>,
    {
        let mut current = match location {
            RelativeLocation::Root => self.root,
            RelativeLocation::Current => self.current_dir,
        };

        for component in Self::parse_path(&name) {
            match component {
                Utf8WindowsComponent::RootDir => current = self.root,
                Utf8WindowsComponent::ParentDir => {
                    if let Some(parent) = current.parent(&self.arena) {
                        current = parent;
                    }
                }
                Utf8WindowsComponent::Normal(part) => {
                    if let Some(directory) = current.children(&self.arena).find(|&id| {
                        self.arena
                            .get(id)
                            .is_some_and(|item| item.get().name().eq_ignore_ascii_case(part))
                    }) {
                        current = directory;
                    } else {
                        current =
                            current.append_value(FsEntry::new_directory(part), &mut self.arena);
                    }
                }
                _ => {}
            }
        }

        current
    }

    /// Sets the current directory to the root.
    #[inline]
    pub const fn set_root(&mut self) {
        self.current_dir = self.root;
    }

    /// Sets the current directory from a path, relative to a [location], creating it and all
    /// necessary parent directories if they do not already exist.
    ///
    /// [location]: RelativeLocation
    pub fn set_directory<T>(&mut self, path: T, location: RelativeLocation)
    where
        T: AsRef<Utf8WindowsPath>,
    {
        self.current_dir = self.create_directory(path, location);
    }

    /// Creates a file from a path relative to a [location], an optional modified at
    /// [datetime], and a position.
    ///
    /// [datetime]: Timestamp
    /// [location]: RelativeLocation
    pub fn create_file<T, D, P>(
        &mut self,
        path: T,
        modified_at: D,
        position: P,
        location: RelativeLocation,
    ) -> Option<NodeId>
    where
        T: AsRef<Utf8WindowsPath>,
        D: Into<Option<Timestamp>>,
        P: Into<u64>,
    {
        let path = path.as_ref();

        let file_name = path.file_name()?;

        let directory = if let Some(parent) = path.parent() {
            self.create_directory(parent, location)
        } else {
            match location {
                RelativeLocation::Root => self.root,
                RelativeLocation::Current => self.current_dir,
            }
        };

        if let Some(file) = directory.children(&self.arena).find(|&id| {
            self.arena
                .get(id)
                .filter(|node| !node.is_removed())
                .is_some_and(|node| node.get().name() == file_name)
        }) {
            Some(file)
        } else {
            let file = FsEntry::new_file(file_name, modified_at, position);
            Some(directory.append_value(file, &mut self.arena))
        }
    }

    /// Creates a link from a path relative to the root.
    pub fn create_link<T, U>(&mut self, path: T, target_path: U) -> Option<NodeId>
    where
        T: AsRef<Utf8WindowsPath>,
        U: Into<CompactString>,
    {
        let path = path.as_ref();

        let link_name = path.file_name()?;

        let directory = if let Some(parent) = path.parent() {
            self.create_directory(parent, RelativeLocation::Root)
        } else {
            self.root
        };

        if let Some(file) = directory.children(&self.arena).find(|&id| {
            self.arena
                .get(id)
                .is_some_and(|node| node.get().name().eq_ignore_ascii_case(link_name))
        }) {
            Some(file)
        } else {
            let file = FsEntry::new_link(link_name, target_path);
            Some(directory.append_value(file, &mut self.arena))
        }
    }

    /// Returns true if the given path exists relative to a [location].
    ///
    /// [location]: RelativeLocation
    pub fn exists<T>(&self, path: T, location: RelativeLocation) -> bool
    where
        T: AsRef<Utf8WindowsPath>,
    {
        self.get(path, location).is_some()
    }

    pub fn get<T>(&self, path: T, location: RelativeLocation) -> Option<&FsEntry>
    where
        T: AsRef<Utf8WindowsPath>,
    {
        self.arena.get(self.get_id(path, location)?).map(Node::get)
    }

    pub fn get_id<T>(&self, path: T, location: RelativeLocation) -> Option<NodeId>
    where
        T: AsRef<Utf8WindowsPath>,
    {
        if path.as_ref().as_str().is_empty() {
            return None;
        }
        let mut current = match location {
            RelativeLocation::Root => self.root,
            RelativeLocation::Current => self.current_dir,
        };

        for component in Self::parse_path(&path) {
            match component {
                Utf8WindowsComponent::RootDir => current = self.root,
                Utf8WindowsComponent::ParentDir => {
                    if let Some(parent) = current.parent(&self.arena) {
                        current = parent;
                    }
                }
                Utf8WindowsComponent::Normal(part) => {
                    if let Some(directory) = current.children(&self.arena).find(|&id| {
                        self.arena
                            .get(id)
                            .is_some_and(|item| item.get().name().eq_ignore_ascii_case(part))
                    }) {
                        current = directory;
                    } else {
                        return None;
                    }
                }
                _ => {}
            }
        }

        Some(current)
    }

    pub fn find(&self, spec: &str) -> Vec<String> {
        let path = Utf8WindowsPath::new(spec);
        let Some(pattern) = path.file_name() else {
            return Vec::new();
        };
        let parent = match path.parent().filter(|p| !p.as_str().is_empty()) {
            Some(parent) => self.get_id(parent, RelativeLocation::Current),
            None => Some(self.current_dir),
        };
        let Some(parent) = parent else {
            return Vec::new();
        };
        let mut names = Vec::new();
        if parent != self.root {
            names.extend(
                [".", ".."]
                    .into_iter()
                    .filter(|name| wildcard_matches(pattern, name))
                    .map(str::to_owned),
            );
        }
        names.extend(
            parent
                .children(&self.arena)
                .filter_map(|id| self.arena.get(id).map(Node::get))
                .map(FsEntry::name)
                .filter(|name| wildcard_matches(pattern, name))
                .map(str::to_owned),
        );
        names
    }

    /// Deletes a path.
    ///
    /// If `flags` contains [`SIMPLE`], the file is deleted relative to the current directory.
    /// If `flags` contains [`DIRECTORY`], the directory is deleted relative to the filesystem root.
    ///
    /// [`SIMPLE`]: DelFlags::SIMPLE
    /// [`DIRECTORY`]: DelFlags::DIRECTORY
    pub fn delete<T>(&mut self, path: T, flags: DelFlags) -> bool
    where
        T: AsRef<str> + Sized,
    {
        let path = path.as_ref();
        if path.is_empty() {
            return false;
        }
        if flags.contains(DelFlags::SIMPLE) {
            let Some(id) = self.get_id(path, RelativeLocation::Current) else {
                return false;
            };
            if self.arena[id].get().is_directory() {
                return false;
            }
            id.remove(&mut self.arena);
            return true;
        }
        if !flags.contains(DelFlags::DIRECTORY) {
            let spec = Utf8WindowsPath::new(path);
            let parent = spec.parent().unwrap_or_else(|| Utf8WindowsPath::new(""));
            for name in self.find(path) {
                if let Some(id) = self.get_id(parent.join(name), RelativeLocation::Current)
                    && !self.arena[id].get().is_directory()
                {
                    id.remove(&mut self.arena);
                }
            }
            // Delete does not set an error for nonexistent files.
            return true;
        }
        let Some(target) = self.get_id(path, RelativeLocation::Root) else {
            return false;
        };
        // Root-only, incomplete UNC, and prefix-only paths must never invalidate
        // the arena root. Windows also refuses to remove its filesystem root.
        if target == self.root || !self.arena[target].get().is_directory() {
            return false;
        }
        let protected: std::collections::HashSet<_> =
            self.current_dir.ancestors(&self.arena).collect();
        if flags.contains(DelFlags::RECURSE) {
            if protected.contains(&target) {
                // Windows can delete contents but cannot remove the working
                // directory or its parents. Preserve the active path itself.
                let descendants: Vec<_> = target.descendants(&self.arena).collect();
                for id in descendants.into_iter().rev() {
                    if !protected.contains(&id) {
                        id.remove(&mut self.arena);
                    }
                }
                false
            } else {
                target.remove_subtree(&mut self.arena);
                true
            }
        } else if self.arena[target].first_child().is_none() && !protected.contains(&target) {
            target.remove(&mut self.arena);
            true
        } else {
            false
        }
    }

    /// Returns an iterator over all entries in the filesystem.
    ///
    /// The iteration order is identical to [`NodeId::descendants`], but with node IDs resolved to
    /// [filesystem entries].
    ///
    /// [filesystem entries]: FsEntry
    pub fn entries(&self) -> impl Iterator<Item = &FsEntry> {
        self.root
            .descendants(&self.arena)
            .filter_map(|id| self.arena.get(id).map(Node::get))
    }

    /// Returns an iterator over all directories in the filesystem.
    ///
    /// The iteration order is identical to [`NodeId::descendants`], but with node IDs resolved to
    /// [filesystem entries].
    ///
    /// [filesystem entries]: FsEntry
    pub fn directories(&self) -> impl Iterator<Item = &FsEntry> {
        self.entries().filter(|item| item.is_directory())
    }

    /// Returns an iterator over all files in the filesystem.
    ///
    /// The iteration order is identical to [`NodeId::descendants`], but with node IDs resolved to
    /// [filesystem entries].
    ///
    /// [filesystem entries]: FsEntry
    pub fn files(&self) -> impl Iterator<Item = &FsEntry> {
        self.entries().filter(|item| item.is_file())
    }

    /// Returns an iterator of all filesystem entries in storage-order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &FsEntry> {
        self.into_iter()
    }
}

fn wildcard_matches(pattern: &str, name: &str) -> bool {
    // The common DOS *.* pattern also matches extensionless names.
    let pattern = if pattern == "*.*" { "*" } else { pattern };
    let pattern: Vec<_> = pattern.to_lowercase().chars().collect();
    let name: Vec<_> = name.to_lowercase().chars().collect();
    let (mut p, mut n, mut star, mut retry) = (0, 0, None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if pattern.get(p) == Some(&'*') {
            star = Some(p);
            p += 1;
            retry = n;
        } else if let Some(position) = star {
            p = position + 1;
            retry += 1;
            n = retry;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

impl fmt::Debug for FileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.debug_pretty_print(&self.arena).fmt(f)
    }
}

impl fmt::Display for FileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.debug_pretty_print(&self.arena).fmt(f)
    }
}

impl Default for FileSystem {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a FileSystem {
    type Item = &'a FsEntry;

    type IntoIter =
        FilterMap<Iter<'a, Node<FsEntry>>, fn(&'a Node<FsEntry>) -> Option<&'a FsEntry>>;

    /// Returns an iterator of all filesystem entries in storage-order.
    fn into_iter(self) -> Self::IntoIter {
        self.arena
            .iter()
            .filter_map(|node| (!node.is_removed()).then_some(node.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_remove_working_directory_but_can_remove_its_contents() {
        let mut fs = FileSystem::new();
        fs.set_directory(r"Temp\Output", RelativeLocation::Root);
        fs.create_file("old.exe", None, 0u64, RelativeLocation::Current)
            .unwrap();
        assert!(!fs.delete(r"Temp\Output", DelFlags::DIRECTORY | DelFlags::RECURSE));
        assert!(!fs.exists("old.exe", RelativeLocation::Current));
        fs.create_file("next.exe", None, 0u64, RelativeLocation::Current)
            .unwrap();
        assert!(fs.exists(r"Temp\Output\next.exe", RelativeLocation::Root));
    }

    #[test]
    fn root_paths_do_not_destroy_the_mock_filesystem() {
        let mut fs = FileSystem::new();
        for path in [r"\", r"\\Uninstall.exe", r"C:\"] {
            assert!(!fs.delete(path, DelFlags::DIRECTORY | DelFlags::RECURSE));
            fs.create_file(r"Plugins\next.dll", None, 0u64, RelativeLocation::Root)
                .unwrap();
        }
        assert!(fs.exists(r"Plugins\next.dll", RelativeLocation::Root));
    }

    #[test]
    fn non_recursive_removal_and_file_wildcards() {
        let mut fs = FileSystem::new();
        fs.create_file(r"Parent\Keep\a.ini", None, 0u64, RelativeLocation::Root)
            .unwrap();
        assert!(!fs.delete(r"Parent\Keep", DelFlags::DIRECTORY));
        assert!(fs.exists(r"Parent\Keep\a.ini", RelativeLocation::Root));
        assert!(fs.delete(r"Parent\Keep\*.INI", DelFlags::empty()));
        assert!(!fs.exists(r"Parent\Keep\a.ini", RelativeLocation::Root));
        assert!(fs.delete(r"Parent\Keep", DelFlags::DIRECTORY));
        assert!(fs.exists("Parent", RelativeLocation::Root));
    }
}
