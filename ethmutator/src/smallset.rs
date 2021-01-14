use fxhash::FxHashSet;
use rand::prelude::*;
use smallvec::SmallVec;

const VEC_THRESHOLD: usize = 128;

/// Set like data structure, which uses a vector until a certain size is reached, then switches to
/// hashset.
/// inspired by LLVM's SmallSet https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/ADT/SmallSet.h
/// This is useful when dealing with small sets of u32 or maybe even u64, where it is faster to
/// quickly scan through a vector instead of doing the whole hashing/bucket thingy.
#[derive(Debug, Clone)]
pub struct SmallSet<T> {
    container: SmallSetContainer<T>,
}

#[derive(Debug, Clone)]
enum SmallSetContainer<T> {
    /// we use the SmallVec here, since we mostly do not expect anything larger than 32 for our uses
    /// of the SmallSet.
    AsVec(SmallVec<[T; 32]>),
    /// we use the FxHashSet, which is optimized for small integer-sized keys. We use SmallSets
    /// mostly for storing u32 and u64 types, where the fxhasher should be the fastest.
    AsHashSet(FxHashSet<T>),
}

use SmallSetContainer::*;

impl<T> SmallSet<T>
where
    T: std::cmp::Eq + std::hash::Hash + std::clone::Clone,
{
    pub fn new() -> SmallSet<T> {
        SmallSet {
            container: AsVec(SmallVec::new()),
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub fn is_empty(&self) -> bool {
        match &self.container {
            AsVec(v) => v.is_empty(),
            AsHashSet(v) => v.is_empty(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.container {
            AsVec(v) => v.len(),
            AsHashSet(v) => v.len(),
        }
    }

    #[inline]
    pub fn contains(&self, value: &T) -> bool {
        match &self.container {
            AsVec(v) => v.contains(value),
            AsHashSet(v) => v.contains(value),
        }
    }

    #[inline]
    pub fn insert(&mut self, value: T) -> bool {
        use std::iter::FromIterator;
        match &mut self.container {
            AsVec(v) => {
                let present = v.contains(&value);
                if !present {
                    v.push(value);
                }
                if v.len() > VEC_THRESHOLD {
                    self.container = AsHashSet(FxHashSet::from_iter(v.drain(0..v.len())));
                }
                !present
            }
            AsHashSet(v) => v.insert(value),
        }
    }

    pub fn choose<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<T> {
        match &self.container {
            AsVec(v) => {
                if v.is_empty() {
                    None
                } else {
                    let i = rng.gen_range(0..v.len());
                    Some(v[i].clone())
                }
            }
            AsHashSet(v) => {
                if v.is_empty() {
                    None
                } else {
                    Some(v.iter().choose(rng).cloned().unwrap())
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_smallset_u32_basics() {
        let mut s = SmallSet::<u32>::new();

        assert!(s.is_empty());

        assert!(s.insert(13));
        assert!(!s.insert(13));
        assert!(s.insert(1));
        assert!(s.insert(1000));
        assert!(s.insert(52));

        assert!(!s.is_empty());

        assert!(s.contains(&1));
        assert!(!s.contains(&2));
        assert!(s.contains(&13));
        assert!(s.contains(&1000));
        assert!(s.contains(&52));

        assert_eq!(s.len(), 4);
    }

    #[test]
    fn test_smallset_u32_transition() {
        let mut s = SmallSet::<u32>::new();

        assert!(s.is_empty());

        assert!(s.insert(13));
        assert!(!s.insert(13));
        assert!(s.insert(1));
        assert!(s.insert(52));

        assert!(!s.is_empty());

        for i in 1000u32..2000u32 {
            s.insert(i);
        }

        assert!(s.contains(&1));
        assert!(!s.contains(&2));
        assert!(s.contains(&13));
        assert!(s.contains(&1000));
        assert!(s.contains(&1500));
        assert!(s.contains(&52));

        assert_eq!(s.len(), 1003);
    }
}
