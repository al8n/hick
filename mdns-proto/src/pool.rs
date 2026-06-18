//! Pluggable backing storage for the protocol state machines.
//!
//! [`Pool<V>`] abstracts over slab-like containers so the proto crate can
//! support multiple storage strategies — `slab::Slab` on alloc-capable targets,
//! or caller-defined types — without baking any one choice into the API.

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

/// Test-only fixed-capacity, FALLIBLE [`Pool`] — a [`slab::Slab`] capped at `N`.
/// Stands in for the removed `heapless` backend so the `Pool` fallible contract
/// and the cache's reactive-eviction-on-capacity-error path stay covered without
/// a `heapless` dependency. Reuses slab's iterators.
#[cfg(all(test, feature = "slab"))]
pub(crate) struct FixedPool<V, const N: usize>(slab::Slab<V>);

/// Capacity error for [`FixedPool`].
#[cfg(all(test, feature = "slab"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FixedPoolFull;

#[cfg(all(test, feature = "slab"))]
impl core::fmt::Display for FixedPoolFull {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("fixed pool capacity exhausted")
  }
}

#[cfg(all(test, feature = "slab"))]
impl core::error::Error for FixedPoolFull {}

#[cfg(all(test, feature = "slab"))]
impl<V, const N: usize> Pool<V> for FixedPool<V, N> {
  type Error = FixedPoolFull;

  type Iter<'a>
    = slab::Iter<'a, V>
  where
    Self: 'a;

  type IterMut<'a>
    = slab::IterMut<'a, V>
  where
    Self: 'a;

  fn new() -> Self {
    Self(slab::Slab::new())
  }

  fn with_capacity(capacity: usize) -> Result<Self, Self::Error> {
    if capacity > N {
      Err(FixedPoolFull)
    } else {
      Ok(Self(slab::Slab::new()))
    }
  }

  fn vacant_key(&self) -> Result<usize, Self::Error> {
    if slab::Slab::len(&self.0) >= N {
      Err(FixedPoolFull)
    } else {
      Ok(slab::Slab::vacant_key(&self.0))
    }
  }

  fn is_empty(&self) -> bool {
    slab::Slab::is_empty(&self.0)
  }

  fn len(&self) -> usize {
    slab::Slab::len(&self.0)
  }

  fn get(&self, key: usize) -> Option<&V> {
    slab::Slab::get(&self.0, key)
  }

  fn get_mut(&mut self, key: usize) -> Option<&mut V> {
    slab::Slab::get_mut(&mut self.0, key)
  }

  fn insert(&mut self, value: V) -> Result<usize, Self::Error> {
    if slab::Slab::len(&self.0) >= N {
      return Err(FixedPoolFull);
    }
    Ok(slab::Slab::insert(&mut self.0, value))
  }

  fn try_remove(&mut self, key: usize) -> Option<V> {
    slab::Slab::try_remove(&mut self.0, key)
  }

  fn iter(&self) -> Self::Iter<'_> {
    slab::Slab::iter(&self.0)
  }

  fn iter_mut(&mut self) -> Self::IterMut<'_> {
    slab::Slab::iter_mut(&mut self.0)
  }
}

#[cfg(test)]
mod tests;
