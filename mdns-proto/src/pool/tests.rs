#[cfg(feature = "heapless")]
#[allow(clippy::unwrap_used)]
mod tests_heapless {
  use super::super::Pool;
  // `heapless::Vec` has inherent `insert(index, element)` and derives `len()` / `get()`
  // from `Deref<Target=[T]>`, so we must use UFCS to call the `Pool<V>` trait methods.
  type P4 = heapless::Vec<Option<u32>, 4>;
  type P2 = heapless::Vec<Option<u32>, 2>;

  #[test]
  fn insert_get_remove_roundtrip() {
    let mut p: P4 = Pool::<u32>::new();
    assert_eq!(Pool::len(&p), 0);
    let k0 = Pool::insert(&mut p, 10).unwrap();
    let k1 = Pool::insert(&mut p, 20).unwrap();
    assert_eq!(Pool::get(&p, k0), Some(&10));
    assert_eq!(Pool::get(&p, k1), Some(&20));
    assert_eq!(Pool::len(&p), 2);
    let removed = Pool::try_remove(&mut p, k0);
    assert_eq!(removed, Some(10));
    assert_eq!(Pool::get(&p, k0), None);
    assert_eq!(Pool::len(&p), 1);
  }

  #[test]
  fn capacity_exhaustion_returns_error() {
    let mut p: P2 = Pool::<u32>::new();
    assert!(Pool::insert(&mut p, 1).is_ok());
    assert!(Pool::insert(&mut p, 2).is_ok());
    assert!(Pool::insert(&mut p, 3).is_err());
    // Full pool: vacant_key reports exhaustion too.
    assert!(Pool::vacant_key(&p).is_err());
  }

  #[test]
  fn with_capacity_vacant_empty_and_iters() {
    assert!(<P2 as Pool<u32>>::with_capacity(2).is_ok());
    assert!(<P2 as Pool<u32>>::with_capacity(3).is_err()); // > N

    let mut p: P4 = Pool::<u32>::new();
    assert!(Pool::is_empty(&p));
    assert_eq!(Pool::vacant_key(&p), Ok(0));
    let k0 = Pool::insert(&mut p, 1).unwrap();
    let k1 = Pool::insert(&mut p, 2).unwrap();
    assert!(!Pool::is_empty(&p));
    assert_eq!(Pool::vacant_key(&p), Ok(2)); // next free slot past the tail

    *Pool::get_mut(&mut p, k0).unwrap() += 100;
    let mut sum = 0;
    for (_, v) in Pool::iter(&p) {
      sum += *v;
    }
    assert_eq!(sum, 101 + 2);
    for (_, v) in Pool::iter_mut(&mut p) {
      *v += 1;
    }
    assert_eq!(Pool::get(&p, k0), Some(&102));
    assert_eq!(Pool::get(&p, k1), Some(&3));

    Pool::try_remove(&mut p, k0); // hole at 0
    assert_eq!(Pool::vacant_key(&p), Ok(0)); // reuses the hole
  }
}

#[cfg(feature = "slab")]
#[allow(clippy::unwrap_used)]
mod tests_slab {
  use super::super::Pool;

  #[test]
  fn slab_pool_trait_capacity_vacant_empty() {
    let mut p: slab::Slab<u32> = Pool::with_capacity(4).unwrap();
    assert!(Pool::is_empty(&p));
    assert_eq!(Pool::vacant_key(&p), Ok(0));
    let _ = Pool::insert(&mut p, 7).unwrap();
    assert!(!Pool::is_empty(&p));
  }
}
