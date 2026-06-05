//! Pluggable backing storage for the protocol state machines.
//!
//! [`Pool<V>`] abstracts over slab-like containers so the proto crate can
//! support multiple storage strategies — `slab::Slab` on alloc-capable
//! targets, `heapless::Vec<Option<V>, N>` on bare-metal `no_alloc`, or
//! caller-defined types — without baking any one choice into the API.

/// Pre-allocated storage for a uniform data type.
pub trait Pool<V> {
  /// The error type raised when capacity is exhausted or invariants are violated.
  type Error: core::error::Error;

  /// The iterator type returned by [`Pool::iter`].
  type Iter<'a>: Iterator<Item = (usize, &'a V)>
  where
    Self: 'a,
    V: 'a;

  /// The iterator type returned by [`Pool::iter_mut`].
  type IterMut<'a>: Iterator<Item = (usize, &'a mut V)>
  where
    Self: 'a,
    V: 'a;

  /// Returns a new, empty pool.
  fn new() -> Self;

  /// Returns a new pool with the specified capacity.
  ///
  /// Returns an error if the pool cannot hold the specified number of entries.
  fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
  where
    Self: Sized;

  /// Returns the key that would be assigned to the next inserted value.
  ///
  /// Returns an error if the pool is full.
  fn vacant_key(&self) -> Result<usize, Self::Error>;

  /// Returns `true` if the pool contains no values.
  fn is_empty(&self) -> bool;

  /// Returns the number of values currently stored.
  fn len(&self) -> usize;

  /// Returns a reference to the value associated with the given key, or `None`.
  fn get(&self, key: usize) -> Option<&V>;

  /// Returns a mutable reference to the value associated with the given key, or `None`.
  fn get_mut(&mut self, key: usize) -> Option<&mut V>;

  /// Inserts a value, returning the key assigned to it.
  ///
  /// Returns an error if the pool is at capacity.
  fn insert(&mut self, value: V) -> Result<usize, Self::Error>;

  /// Removes the value associated with the given key, returning it if it existed.
  fn try_remove(&mut self, key: usize) -> Option<V>;

  /// Returns an iterator over `(key, &value)` pairs.
  fn iter(&self) -> Self::Iter<'_>;

  /// Returns an iterator over `(key, &mut value)` pairs.
  ///
  /// Enables single-pass eager mutation of multiple pool entries (e.g.
  /// applying an inbound event to every matching entry without
  /// collecting matching keys into a separate Vec).  Required by
  /// `Endpoint::handle` to apply `QueryEvent::Answer` to all matching
  /// owned queries in one pass.
  fn iter_mut(&mut self) -> Self::IterMut<'_>;
}

#[cfg(feature = "slab")]
#[cfg_attr(docsrs, doc(cfg(feature = "slab")))]
impl<T> Pool<T> for slab::Slab<T> {
  type Error = core::convert::Infallible;

  type Iter<'a>
    = slab::Iter<'a, T>
  where
    Self: 'a;

  type IterMut<'a>
    = slab::IterMut<'a, T>
  where
    Self: 'a;

  #[inline]
  fn new() -> Self {
    slab::Slab::new()
  }

  #[inline]
  fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    Ok(slab::Slab::with_capacity(capacity))
  }

  #[inline]
  fn vacant_key(&self) -> Result<usize, Self::Error> {
    Ok(slab::Slab::vacant_key(self))
  }

  #[inline]
  fn is_empty(&self) -> bool {
    slab::Slab::is_empty(self)
  }

  #[inline]
  fn len(&self) -> usize {
    slab::Slab::len(self)
  }

  #[inline]
  fn get(&self, key: usize) -> Option<&T> {
    slab::Slab::get(self, key)
  }

  #[inline]
  fn get_mut(&mut self, key: usize) -> Option<&mut T> {
    slab::Slab::get_mut(self, key)
  }

  #[inline]
  fn insert(&mut self, value: T) -> Result<usize, Self::Error> {
    Ok(slab::Slab::insert(self, value))
  }

  #[inline]
  fn try_remove(&mut self, key: usize) -> Option<T> {
    slab::Slab::try_remove(self, key)
  }

  #[inline]
  fn iter(&self) -> Self::Iter<'_> {
    slab::Slab::iter(self)
  }

  #[inline]
  fn iter_mut(&mut self) -> Self::IterMut<'_> {
    slab::Slab::iter_mut(self)
  }
}

#[cfg(feature = "heapless")]
#[cfg_attr(docsrs, doc(cfg(feature = "heapless")))]
mod heapless_impl {
  use super::Pool;

  /// Error returned by the heapless [`Pool`] impl when capacity is exhausted.
  #[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
  #[non_exhaustive]
  #[error("heapless Pool capacity exhausted")]
  pub struct HeaplessCapacityError;

  /// Iterator over occupied `(key, &value)` pairs in a heapless pool.
  pub struct HeaplessIter<'a, V> {
    inner: core::iter::Enumerate<core::slice::Iter<'a, Option<V>>>,
  }

  impl<'a, V> Iterator for HeaplessIter<'a, V> {
    type Item = (usize, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
      for (idx, slot) in self.inner.by_ref() {
        if let Some(v) = slot {
          return Some((idx, v));
        }
      }
      None
    }
  }

  /// Iterator over occupied `(key, &mut value)` pairs in a heapless pool.
  pub struct HeaplessIterMut<'a, V> {
    inner: core::iter::Enumerate<core::slice::IterMut<'a, Option<V>>>,
  }

  impl<'a, V> Iterator for HeaplessIterMut<'a, V> {
    type Item = (usize, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
      for (idx, slot) in self.inner.by_ref() {
        if let Some(v) = slot {
          return Some((idx, v));
        }
      }
      None
    }
  }

  impl<V, const N: usize> Pool<V> for heapless::Vec<Option<V>, N> {
    type Error = HeaplessCapacityError;

    type Iter<'a>
      = HeaplessIter<'a, V>
    where
      Self: 'a,
      V: 'a;

    type IterMut<'a>
      = HeaplessIterMut<'a, V>
    where
      Self: 'a,
      V: 'a;

    #[inline]
    fn new() -> Self {
      heapless::Vec::new()
    }

    #[inline]
    fn with_capacity(capacity: usize) -> Result<Self, Self::Error> {
      if capacity > N {
        return Err(HeaplessCapacityError);
      }
      Ok(heapless::Vec::new())
    }

    #[inline]
    fn vacant_key(&self) -> Result<usize, Self::Error> {
      for (idx, slot) in self.as_slice().iter().enumerate() {
        if slot.is_none() {
          return Ok(idx);
        }
      }
      if heapless::Vec::len(self) < N {
        return Ok(heapless::Vec::len(self));
      }
      Err(HeaplessCapacityError)
    }

    #[inline]
    fn is_empty(&self) -> bool {
      self.as_slice().iter().all(Option::is_none)
    }

    #[inline]
    fn len(&self) -> usize {
      self.as_slice().iter().filter(|s| s.is_some()).count()
    }

    #[inline]
    fn get(&self, key: usize) -> Option<&V> {
      self.as_slice().get(key).and_then(Option::as_ref)
    }

    #[inline]
    fn get_mut(&mut self, key: usize) -> Option<&mut V> {
      self.as_mut_slice().get_mut(key).and_then(Option::as_mut)
    }

    fn insert(&mut self, value: V) -> Result<usize, Self::Error> {
      for (idx, slot) in self.as_mut_slice().iter_mut().enumerate() {
        if slot.is_none() {
          *slot = Some(value);
          return Ok(idx);
        }
      }
      let idx = heapless::Vec::len(self);
      heapless::Vec::push(self, Some(value)).map_err(|_| HeaplessCapacityError)?;
      Ok(idx)
    }

    #[inline]
    fn try_remove(&mut self, key: usize) -> Option<V> {
      self.as_mut_slice().get_mut(key).and_then(Option::take)
    }

    #[inline]
    fn iter(&self) -> Self::Iter<'_> {
      HeaplessIter {
        inner: self.as_slice().iter().enumerate(),
      }
    }

    #[inline]
    fn iter_mut(&mut self) -> Self::IterMut<'_> {
      HeaplessIterMut {
        inner: self.as_mut_slice().iter_mut().enumerate(),
      }
    }
  }
}

#[cfg(feature = "heapless")]
pub use heapless_impl::HeaplessCapacityError;

#[cfg(test)]
mod tests;
