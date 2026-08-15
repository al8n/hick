use libc::cmsghdr;

// Each address type is used only inside its matching capability-gated cmsg arm
// below (`IpAddr` in both); gate the imports the same way so platforms that lack
// a pktinfo layout (e.g. BSDs have no `in_pktinfo`) don't see an unused import.
#[cfg(any(has_ip_pktinfo, has_ipv6_pktinfo))]
use core::net::IpAddr;
#[cfg(has_ip_pktinfo)]
use core::net::Ipv4Addr;
#[cfg(has_ipv6_pktinfo)]
use core::net::Ipv6Addr;

#[cfg(any(has_ip_pktinfo, has_ipv6_pktinfo))]
use hick_udp::onlink::{DestinationWitness, IfaceWitness};

use super::RecvMeta;

/// One ancillary control message inside a filled control buffer.
///
/// # Why a raw pointer rather than a `&'a cmsghdr`
///
/// [`CMsgRef::data`] hands back a pointer to the payload that FOLLOWS the
/// header, and callers read `size_of::<T>()` bytes through it. A `&'a cmsghdr`
/// cannot license that read: under Stacked Borrows the retag that creates the
/// reference narrows provenance to the `size_of::<cmsghdr>()` bytes of the
/// header itself, so every payload byte derived from it is out of bounds *for
/// that tag* even though it sits well inside the control buffer the kernel
/// filled — the arithmetic is right and the tag is wrong. Miri said exactly
/// that: "attempting a read access using `<tag>` at `alloc[0xc]`, but that tag
/// does not exist in the borrow stack for this location", against a tag
/// "created by a SharedReadOnly retag at offsets `[0x0..0xc]`" (0xc =
/// `size_of::<cmsghdr>()` on Darwin).
///
/// So the header is held as a `*const cmsghdr` whose provenance spans the WHOLE
/// control buffer — [`CMsgIter`] anchors every header pointer it mints to the
/// buffer's own base pointer — the borrow is carried by `PhantomData` instead
/// of by the pointer, and the header's fields are read through `&raw const`
/// place projections, which compute an address without materialising a
/// reference and therefore without re-narrowing the tag.
///
/// # Why the payload length is a field
///
/// `cmsg_len` is a number the KERNEL wrote into a buffer, and on a truncated
/// receive it describes a cmsg longer than the bytes that actually arrived —
/// `MSG_CTRUNC` on Darwin copies a prefix of the final cmsg while leaving its
/// original `cmsg_len` intact. Recomputing the payload length from that field
/// on demand therefore reports a length the buffer does not back, and the
/// caller-side `data_len() >= size_of::<T>()` guard passes on it. So the length
/// is not recomputed: [`CMsgIter`] validates `cmsg_len` against the bytes that
/// remain and stores the surviving bound here at construction. A `CMsgRef` that
/// exists is a cmsg whose payload is present, and no caller can ask it for a
/// length the buffer does not hold.
pub(crate) struct CMsgRef<'a> {
  hdr: *const cmsghdr,
  /// Payload bytes PROVEN present in the control buffer — `cmsg_len` minus the
  /// payload offset, already clamped to what the buffer actually holds. See
  /// [`CMsgIter::next`], which is the only thing that may set it.
  data_len: usize,
  _lt: core::marker::PhantomData<&'a [u8]>,
}

impl CMsgRef<'_> {
  /// Read one header field without forming a `&cmsghdr`.
  ///
  /// `read_unaligned` rather than a plain read: it compiles to the same thing
  /// for these word-sized fields on every supported target, and it keeps the
  /// accessors sound on their own terms instead of leaning on
  /// [`CMsgIter::new`]'s alignment assert.
  ///
  /// # Safety
  ///
  /// `field` must be a `&raw const` projection of a header that [`CMsgIter`]
  /// has established lies wholly inside the control buffer, so it is valid for
  /// reads of `T`.
  #[inline]
  unsafe fn field<T: Copy>(field: *const T) -> T {
    // SAFETY: the caller passes a projection of a header pointer derived from
    // the control buffer and bounds-checked against it.
    unsafe { core::ptr::read_unaligned(field) }
  }

  #[inline]
  pub(crate) fn level(&self) -> libc::c_int {
    // SAFETY: `hdr` addresses a `cmsghdr` inside the buffer borrowed for `'a`;
    // `&raw const` projects to the field without retagging.
    unsafe { Self::field(&raw const (*self.hdr).cmsg_level) }
  }

  #[inline]
  pub(crate) fn ty(&self) -> libc::c_int {
    // SAFETY: as in `level`.
    unsafe { Self::field(&raw const (*self.hdr).cmsg_type) }
  }

  /// Number of payload bytes this cmsg actually carries — `cmsg_len` minus the
  /// header/alignment offset, saturating so a corrupt short cmsg yields 0, and
  /// clamped to the bytes the control buffer really holds.
  ///
  /// Both halves are established once, in [`CMsgIter::next`], and read back
  /// from a field here; see the type-level note on why this is not recomputed
  /// from `cmsg_len` on demand.
  ///
  /// Callers must still check `data_len() >= size_of::<T>()` before reading the
  /// payload as `T` via [`CMsgRef::data`]: this is the length of the payload,
  /// not a promise that it is as wide as any particular `T`.
  #[inline]
  pub(crate) fn data_len(&self) -> usize {
    self.data_len
  }

  /// View the cmsg payload as `T`.
  ///
  /// # Safety
  ///
  /// - Caller must guarantee `T` matches the actual cmsg payload type/size,
  ///   and must have checked `data_len() >= size_of::<T>()` — that bound is
  ///   verified against the control buffer (see the type-level note), so
  ///   honouring it is what keeps the read inside the buffer as well as inside
  ///   the cmsg. The underlying buffer must outlive any read through the
  ///   returned pointer.
  /// - **Alignment caveat:** `CMSG_DATA` is only guaranteed to be aligned
  ///   to `align_of::<libc::cmsghdr>()` (4 bytes on Darwin). When
  ///   `align_of::<T>() > align_of::<libc::cmsghdr>()` — for example
  ///   `libc::timeval` and `libc::timespec` on Darwin, which want 8-byte
  ///   alignment — callers MUST use `core::ptr::read_unaligned` on the
  ///   returned pointer instead of dereferencing it. Plain `*ptr` reads
  ///   are UB on misaligned data.
  #[inline]
  pub(crate) unsafe fn data<T>(&self) -> *const T {
    // SAFETY: caller asserts T matches. `CMSG_DATA` is a pure `offset` off the
    // header pointer, so the result inherits `hdr`'s provenance — and `hdr`
    // spans the whole control buffer (see the type's docs and `CMsgIter`),
    // which is what makes the payload bytes the caller then reads in bounds
    // FOR THIS TAG and not merely in bounds for the allocation. The caller is
    // responsible for honoring T's alignment (see the alignment caveat above)
    // — `*ptr` reads of misaligned data are UB, and they must use
    // `core::ptr::read_unaligned` in that case.
    unsafe { libc::CMSG_DATA(self.hdr) as *const T }
  }
}

/// Iterate ancillary control messages in a filled control buffer.
///
/// The buffer must be aligned to `align_of::<cmsghdr>()` — see
/// [`CMsgIter::new`]. In production this is satisfied by routing the kernel's
/// fill through a `cmsghdr`-aligned scratch buffer.
///
/// # Why this forms no pointer libc could have formed
///
/// The walk is pure integer arithmetic over an `off`/`len` pair, and a pointer
/// is derived from `base` only once the offset it names has been proven to hold
/// a whole header. `CMSG_FIRSTHDR` and `CMSG_NXTHDR` are NOT USED. That is not
/// stylistic:
///
/// * **`CMSG_NXTHDR` can be UB to call at all.** On Android it is
///   `let next = (cmsg as usize + CMSG_ALIGN(cmsg_len)) as *mut cmsghdr;` and
///   then `if (next.offset(1)) as usize > max` — libc forms a pointer one
///   `cmsghdr` PAST its candidate before comparing anything, so a candidate at
///   the end of the buffer offsets past the end of the allocation. Validating
///   the return value cannot help: the UB is inside the macro, before it
///   returns. Our own `AlignedCtrlBuf` is a fixed 512 bytes, so an ordinary
///   full buffer whose last cmsg ends exactly at 512 reaches it while parsing
///   well-formed ancillary data — a kernel-shaped case, not a corrupt-input
///   one. (`libc-0.2.189`, `src/unix/linux_like/android/mod.rs:3471`. Linux's
///   own copy in `linux_l4re_shared.rs` uses `wrapping_add` and is fine;
///   Apple/FreeBSD/DragonFly/NetBSD/OpenBSD compute entirely in `usize` and
///   are also fine. Android is the one that offsets a raw pointer.)
/// * **`CMSG_NXTHDR` is not a bounds check.** On Darwin and the BSDs it
///   computes `cmsg + CMSG_ALIGN(cmsg_len)`, which for a `cmsg_len` of zero is
///   the header it started from, so a walk that trusts it REPEATS THAT HEADER
///   FOR EVER.
/// * **Its arithmetic is unchecked.** `CMSG_ALIGN(len)` is `(len + ALIGNBYTES)
///   & !ALIGNBYTES` on every supported target, and `cmsg as usize + ...` is a
///   plain `+`. A large `cmsg_len` overflows before any comparison happens.
///
/// # What is computed instead
///
/// The stride to the next header is `CMSG_SPACE(data_len)` — a pointer-free
/// length macro that encodes each target's own `CMSG_ALIGN`, so nothing here
/// re-derives an alignment constant by hand (a hand-rolled `apple ? 4 :
/// size_of::<usize>()` is wrong on BSD arches whose `_ALIGNBYTES` differs from
/// the pointer width, e.g. NetBSD/aarch64, where it is 4). It is the same
/// quantity `CMSG_NXTHDR` advances by: with `cmsg_len == CMSG_LEN(data_len) ==
/// A(hdr) + data_len` and `A` idempotent on its own output, `A(cmsg_len) =
/// A(hdr) + A(data_len) = CMSG_SPACE(data_len)`.
///
/// Before any cmsg is yielded [`CMsgIter::next`] establishes, in order: a
/// complete header is present; `cmsg_len` covers its own header and does not
/// exceed the bytes that remain; the payload offset is inside the buffer; and
/// the successor offset both clears the cmsg just read and leaves room for a
/// WHOLE header inside `len`. Every step is `checked_*`. Anything else FUSES
/// the walk — a malformed `cmsg_len` is the only route to the next header, so
/// once it is unusable nothing beyond it is recoverable, and repeating or
/// guessing is worse than stopping.
///
/// This is `hick-udp`'s `CmsgIter`, arrived at from the other side: same
/// pointer-free stride, same three validations, over the same kernel ABI. The
/// two implementations exist because they parse into different types, and every
/// finding against this one so far has been a place where it had not yet
/// converged.
///
/// The header pointer handed to a [`CMsgRef`] is derived from `base` — see
/// [`CMsgIter::anchor`] — so the payload pointer a caller ultimately reads
/// through carries provenance over the entire control buffer.
pub(crate) struct CMsgIter<'a> {
  /// The control buffer's own base pointer, kept as the provenance root for
  /// every header pointer minted below. Never dereferenced through directly.
  base: *const u8,
  /// The control buffer's length. Authoritative for every bound below. No
  /// `msghdr` is kept beside it: with libc's pointer macros gone there is
  /// nothing to hand one to, and `msg_controllen` is a narrower integer type on
  /// the BSDs than the length it would be copied from.
  len: usize,
  /// Byte offset of the next candidate header, or `None` once the walk has
  /// ended — either normally or by fusing on malformed input.
  next: Option<usize>,
  _lt: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> CMsgIter<'a> {
  /// Wrap a filled control buffer for iteration.
  ///
  /// # Panics
  ///
  /// Panics if `buf` is not aligned to `align_of::<cmsghdr>()`; reading a
  /// `cmsghdr` through a misaligned pointer is undefined behaviour, so we
  /// refuse rather than silently invoke UB.
  pub(crate) fn new(buf: &'a [u8]) -> Self {
    assert!(
      buf.as_ptr().cast::<cmsghdr>().is_aligned(),
      "control buffer is not aligned for cmsghdr"
    );
    let base = buf.as_ptr();
    let len = buf.len();
    // The first header is at offset 0 when one fits — which is all
    // `CMSG_FIRSTHDR` says on every supported target (`msg_controllen >=
    // size_of::<cmsghdr>()` then `msg_control`, else null; `linux_like/mod.rs`
    // and `bsd/mod.rs` are byte-for-byte the same test). Stating it here costs
    // nothing and keeps the `msghdr` this walk no longer needs out of the type.
    Self {
      base,
      len,
      next: (len >= core::mem::size_of::<cmsghdr>()).then_some(0),
      _lt: core::marker::PhantomData,
    }
  }

  /// Offset of the header FOLLOWING the one at `off`, or `None` when the buffer
  /// holds no further whole header or its own arithmetic cannot be trusted.
  ///
  /// Everything here is integers, and every step is checked, because libc's
  /// version of this is neither. Three things must hold before an offset is
  /// handed back:
  ///
  /// * the stride is representable — `CMSG_SPACE` takes and returns `c_uint`
  ///   while computing in `usize`, so a `data_len` near `u32::MAX` truncates on
  ///   return to something smaller than the cmsg it was meant to skip;
  /// * the stride actually CLEARS the cmsg just read (`stride >= cmsg_len`), so
  ///   the walk cannot be handed back a position at or before where it started;
  /// * a WHOLE successor header fits — `next + size_of::<cmsghdr>() <= len`,
  ///   not merely `next <= len`. Its start being inside the buffer says nothing
  ///   about the header that would be read there.
  #[inline]
  fn successor(off: usize, cmsg_len: usize, data_len: usize, len: usize) -> Option<usize> {
    let dl = u32::try_from(data_len).ok()?;
    // SAFETY: CMSG_SPACE is pure length arithmetic — it takes an integer and
    // dereferences no memory (libc marks it `unsafe` by convention only).
    let stride = unsafe { libc::CMSG_SPACE(dl) } as usize;
    if stride < cmsg_len {
      return None;
    }
    let next = off.checked_add(stride)?;
    (next.checked_add(core::mem::size_of::<cmsghdr>())? <= len).then_some(next)
  }

  /// Derive a header pointer from the buffer's own base pointer.
  ///
  /// This is the ONLY place a pointer is formed, and it takes an offset that
  /// [`CMsgIter::next`] has already proven names a whole header inside the
  /// buffer. Deriving from `base` is what gives the result — and the payload
  /// pointer [`CMsgRef::data`] later offsets out of it — provenance over the
  /// whole control buffer rather than over one header or over nothing at all.
  ///
  /// Deriving a pointer for an address does not VALIDATE that address, and must
  /// not be mistaken for having done so. The validation is the checked integer
  /// arithmetic in [`CMsgIter::next`] and [`CMsgIter::successor`], which runs
  /// first and never forms a pointer to test a candidate — the mistake libc's
  /// `CMSG_NXTHDR` makes on Android, where `next.offset(1)` is evaluated to
  /// decide whether `next` was in range.
  #[inline]
  fn anchor(base: *const u8, off: usize) -> *const cmsghdr {
    base.wrapping_add(off).cast::<cmsghdr>()
  }
}

impl<'a> Iterator for CMsgIter<'a> {
  type Item = CMsgRef<'a>;

  // `cmsg_len` is `usize` on Linux but `socklen_t` (u32) on the BSDs/macOS, so
  // the `as usize` is platform-conditionally necessary.
  #[allow(clippy::unnecessary_cast)]
  fn next(&mut self) -> Option<Self::Item> {
    // `take` fuses by default: every path out of here leaves the walk ended
    // unless it explicitly sets a validated successor at the bottom.
    let off = self.next.take()?;
    let hdr_size = core::mem::size_of::<cmsghdr>();
    // `off + hdr_size <= self.len` is guaranteed by whichever of `new` or
    // `successor` set it, so this cannot wrap.
    let remaining = self.len - off;
    // A whole header must be present before a single field of it is read.
    if remaining < hdr_size {
      return None;
    }
    let hdr = Self::anchor(self.base, off);
    // SAFETY: the check above puts all `size_of::<cmsghdr>()` bytes of the
    // header inside the buffer, and `hdr` is derived from that buffer's base.
    let cmsg_len = unsafe { CMsgRef::field(&raw const (*hdr).cmsg_len) } as usize;
    // `cmsg_len` must cover its own header, and must not claim more bytes than
    // the buffer holds. THE SECOND TEST IS THE TRUNCATION CASE: on a Darwin
    // `MSG_CTRUNC` receive the kernel copies a prefix of the final cmsg and
    // leaves `cmsg_len` describing the whole of it, so without this the payload
    // bound below would be a length the buffer does not back.
    if cmsg_len < hdr_size || cmsg_len > remaining {
      return None;
    }
    // The payload begins at `CMSG_LEN(0)` — the header size rounded up to the
    // platform's cmsg alignment, which exceeds `size_of::<cmsghdr>()` on the
    // BSDs. Pure length arithmetic, no pointer.
    // SAFETY: CMSG_LEN is a pure size macro (no pointer deref).
    let data_start = unsafe { libc::CMSG_LEN(0) } as usize;
    // A cmsg whose padded payload offset runs off the end carries no payload
    // this buffer can serve, and `CMSG_DATA` would compute a pointer past the
    // end of the allocation just to describe it. Refuse rather than form it.
    if data_start > remaining {
      return None;
    }
    // Saturating, so a `cmsg_len` too short to reach the payload offset yields
    // an empty payload rather than wrapping; then clamped to the bytes actually
    // present, which after the `cmsg_len > remaining` test above is a
    // belt-and-braces bound rather than the load-bearing one.
    let data_len = cmsg_len
      .saturating_sub(data_start)
      .min(remaining - data_start);
    // The successor is computed, checked, and only then believed — no pointer
    // is formed for a candidate position, which is the whole point (see the
    // type-level note on Android's `next.offset(1)`).
    self.next = Self::successor(off, cmsg_len, data_len, self.len);
    Some(CMsgRef {
      hdr,
      data_len,
      _lt: core::marker::PhantomData,
    })
  }
}

// Windows iteration mirrors this shape over WSACMSGHDR / `WSA_CMSG_*` macros;
// added alongside the Windows recv path.

/// Encode outbound cmsgs into a caller-provided byte buffer.
///
/// The buffer must outlive any borrow of the builder; the builder writes
/// `cmsghdr` headers and payloads in place and tracks how many bytes have been
/// consumed. Call [`CMsgBuilder::finish`] to get the final `msg_controllen`.
pub(crate) struct CMsgBuilder<'a> {
  buf: &'a mut [u8],
  cursor: usize,
}

impl<'a> CMsgBuilder<'a> {
  /// Construct a builder over `buf`.
  ///
  /// # Panics
  ///
  /// Panics if `buf` is not aligned to `align_of::<cmsghdr>()`. Writing a
  /// `cmsghdr` through a misaligned pointer is undefined behaviour, so we
  /// refuse rather than silently invoke UB — mirrors [`CMsgIter::new`]'s
  /// precondition.
  pub(crate) fn new(buf: &'a mut [u8]) -> Self {
    assert!(
      buf.as_ptr().cast::<cmsghdr>().is_aligned(),
      "control buffer is not aligned for cmsghdr"
    );
    // recvmsg/sendmsg expect the inter-cmsg padding bytes to be zero; just
    // zero the whole buffer up front so any subsequent walk — this crate's or
    // the kernel's — sees well-defined padding.
    for b in buf.iter_mut() {
      *b = 0;
    }
    Self { buf, cursor: 0 }
  }

  /// Append a cmsg with payload `value: T`.
  ///
  /// Returns `Err(())` if the buffer doesn't have `CMSG_SPACE(sizeof T)` bytes
  /// remaining (i.e. the cmsg wouldn't fit). On success, the cursor advances
  /// past the encoded cmsg + alignment padding.
  pub(crate) fn push<T: Copy>(
    &mut self,
    level: libc::c_int,
    ty: libc::c_int,
    value: &T,
  ) -> Result<(), ()> {
    let payload_bytes = core::mem::size_of::<T>();
    // SAFETY: CMSG_SPACE is a pure macro over its size argument; no pointers.
    let space = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
    let end = self.cursor.checked_add(space).ok_or(())?;
    if end > self.buf.len() {
      return Err(());
    }
    // SAFETY: we just bounds-checked `space`, and `new()` enforced that the
    // buffer is aligned to `align_of::<cmsghdr>()`, so the header store at
    // `buf + cursor` honours `cmsghdr`'s alignment. `CMSG_DATA(hdr)` only
    // guarantees `cmsghdr`-alignment for the payload — which may be looser
    // than `align_of::<T>()` (e.g. `timeval` on Darwin) — so the payload is
    // written via `write_unaligned`, matching the rule documented on
    // [`CMsgRef::data`].
    unsafe {
      let hdr = self.buf.as_mut_ptr().add(self.cursor) as *mut cmsghdr;
      (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
      (*hdr).cmsg_level = level;
      (*hdr).cmsg_type = ty;
      let data = libc::CMSG_DATA(hdr) as *mut T;
      core::ptr::write_unaligned(data, *value);
    }
    self.cursor = end;
    Ok(())
  }

  /// Append a cmsg whose payload is already a **byte image**.
  ///
  /// # Why a second path rather than another `push::<T>` caller
  ///
  /// [`Self::push`] stores its payload with a *typed* `write_unaligned::<T>`,
  /// and a typed copy does not preserve padding initializedness: for a `T` that
  /// has padding — `libc::timeval` is `{ time_t, suseconds_t }`, 12 bytes of
  /// fields in a 16-byte type on Apple/aarch64 — the destination's padding bytes
  /// become UNINITIALIZED, and reading the encoded range back as `&[u8]` is then
  /// undefined behaviour.
  ///
  /// **Pre-zeroing the destination does not save it.** [`Self::new`] already
  /// zeroes the whole buffer, and the typed write de-initializes that padding
  /// again regardless of what the destination held. That is the trap in the
  /// obvious fix, which is why the answer is to keep a padded struct out of
  /// `push::<T>` entirely rather than to prepare the buffer for it.
  ///
  /// So a caller whose encoded bytes must stay readable as `[u8]` builds the
  /// payload field by field, at each `core::mem::offset_of!` position inside a
  /// zeroed buffer, and hands the result here. Copying `[u8]` to `[u8]`
  /// initializes every byte it writes and de-initializes nothing.
  ///
  /// The header setup mirrors [`Self::push`] line for line, `CMSG_DATA`
  /// included, so the two paths cannot drift on where a payload begins.
  #[cfg(test)]
  pub(crate) fn push_bytes(
    &mut self,
    level: libc::c_int,
    ty: libc::c_int,
    payload: &[u8],
  ) -> Result<(), ()> {
    // SAFETY: CMSG_SPACE is a pure macro over its size argument; no pointers.
    let space = unsafe { libc::CMSG_SPACE(payload.len() as u32) } as usize;
    let end = self.cursor.checked_add(space).ok_or(())?;
    if end > self.buf.len() {
      return Err(());
    }
    // SAFETY: `space` is bounds-checked above and `new()` enforced the buffer's
    // `cmsghdr` alignment, so the header store is aligned. The header fields are
    // assigned INDIVIDUALLY rather than by storing a whole `cmsghdr` value: a
    // whole-struct store would de-initialize `cmsghdr`'s own padding (musl's
    // `__pad1`) exactly the way `push`'s typed payload store does. The payload
    // is then a byte-to-byte `copy_nonoverlapping` out of an initialized slice,
    // which can neither require nor destroy initializedness anywhere.
    unsafe {
      let hdr = self.buf.as_mut_ptr().add(self.cursor) as *mut cmsghdr;
      (*hdr).cmsg_len = libc::CMSG_LEN(payload.len() as u32) as _;
      (*hdr).cmsg_level = level;
      (*hdr).cmsg_type = ty;
      let data = libc::CMSG_DATA(hdr);
      core::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload.len());
    }
    self.cursor = end;
    Ok(())
  }

  /// Consume the builder and return the number of bytes written, i.e. the
  /// `msg_controllen` value to hand to `sendmsg`.
  #[inline]
  pub(crate) fn finish(self) -> usize {
    self.cursor
  }
}

/// Boxed 512-byte ancillary buffer whose backing storage is ≥8-byte aligned,
/// which is what `compio-net`'s `recv_msg` / `send_msg` assert for the
/// control parameter and what [`CMsgIter::new`] requires for sound walking.
///
/// `Vec<u8>::with_capacity` does not guarantee anything beyond alignment 1
/// in the type system, so we own a `Box<AlignedStorage>` whose inner type is
/// a `#[repr(align(8))]` array. The wrapper implements `IoBuf` / `IoBufMut`
/// / `SetLen` over a manually tracked `init_len`; `SetLen::set_len` accepts
/// values up to `CMSG_CAP` and never resizes (the buffer is fixed-size).
///
/// # Why the capacity is a security parameter and not a tuning knob
///
/// `MSG_CTRUNC` — the kernel saying THIS buffer was too small — is the only
/// thing that mints [`hick_udp::onlink::DestinationWitness::Lost`], and that
/// witness REFUSES. A buffer sized too small is therefore a self-inflicted
/// outage wearing the shape of a security decision, and the figure has to be
/// measured against what this crate actually enables rather than picked. It was
/// 256 with nothing behind that number;
/// `control_buffer_holds_every_cmsg_this_target_enables` now sums
/// `libc::CMSG_SPACE` over every enabled cmsg at its widest payload and requires
/// the total to fit TWICE over. On FreeBSD/amd64 the worst case is 152 bytes
/// (`IP_RECVDSTADDR` 24 + `IP_RECVIF` 72 + `IP_RECVTTL` 24 + `SCM_TIMESTAMP`
/// 32), which fits 256 once but not twice — hence 512, matching `hick-udp`'s
/// `CmsgBuf`, whose recv path enables the same set on the same socket.
pub(super) struct AlignedCtrlBuf {
  storage: Box<AlignedCtrlStorage>,
  init_len: usize,
}

const CMSG_CAP: usize = 512;

#[repr(align(8))]
struct AlignedCtrlStorage([u8; CMSG_CAP]);

impl AlignedCtrlBuf {
  pub fn new() -> Self {
    Self {
      storage: Box::new(AlignedCtrlStorage([0u8; CMSG_CAP])),
      init_len: 0,
    }
  }

  /// Build a control buffer pre-filled with `src` (used for `send_msg`).
  ///
  /// # Panics
  ///
  /// Panics if `src.len() > CMSG_CAP` — outbound mDNS cmsgs (PKTINFO,
  /// HOPLIMIT) are well under that, so the static cap is fine.
  pub fn from_slice(src: &[u8]) -> Self {
    assert!(
      src.len() <= CMSG_CAP,
      "outbound cmsg payload {} exceeds CMSG_CAP={CMSG_CAP}",
      src.len()
    );
    let mut buf = Self::new();
    buf.storage.0[..src.len()].copy_from_slice(src);
    buf.init_len = src.len();
    buf
  }

  /// Return the initialised portion as a `&[u8]`, clamped to the actual
  /// fill length reported by the kernel.
  pub fn filled(&self, kernel_len: usize) -> &[u8] {
    let n = kernel_len.min(CMSG_CAP);
    &self.storage.0[..n]
  }
}

impl compio_buf::IoBuf for AlignedCtrlBuf {
  fn as_init(&self) -> &[u8] {
    &self.storage.0[..self.init_len]
  }
}

impl compio_buf::IoBufMut for AlignedCtrlBuf {
  fn as_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
    let ptr = self.storage.0.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>;
    // SAFETY: `storage` owns a fixed `[u8; CMSG_CAP]` (all zeroed at
    // construction), so the pointer is valid for `CMSG_CAP` bytes and the
    // bytes are initialised — treating them as `MaybeUninit<u8>` is sound.
    unsafe { core::slice::from_raw_parts_mut(ptr, CMSG_CAP) }
  }
}

impl compio_buf::SetLen for AlignedCtrlBuf {
  unsafe fn set_len(&mut self, len: usize) {
    debug_assert!(len <= CMSG_CAP);
    self.init_len = len.min(CMSG_CAP);
  }
}

pub(super) fn enable_recv_cmsgs(sock: &std::net::UdpSocket) -> std::io::Result<()> {
  use std::os::fd::AsRawFd;
  let fd = sock.as_raw_fd();
  let on: libc::c_int = 1;
  // Apply ONLY the cmsg options for this socket's address family. The IPv4
  // options (`IPPROTO_IP`/`IP_PKTINFO`/`IP_RECVTTL`) return `EINVAL` on an
  // `AF_INET6` socket and vice-versa, so a blanket apply made every v6-only /
  // dual-stack endpoint fail construction (the wrong-family `setsockopt`
  // bubbled up through `from_std` before any datagram could flow). mDNS binds
  // a separate single-family socket per family, so `local_addr` is the
  // authoritative family selector.
  //
  // The capability `cfg`s (emitted by `build.rs`) compose WITH this runtime
  // family check: a cfg gates "does this target define the constant at all"
  // (so an exotic Unix that lacks it still compiles), while `is_v6` gates "is
  // this socket that family" (so we never apply the wrong-family option). Both
  // are required. `fd`/`on`/`is_v6` are touched unconditionally below so they
  // never read as unused on a target where every option's cfg is off.
  let is_v6 = matches!(sock.local_addr()?, std::net::SocketAddr::V6(_));
  let _ = (fd, on, is_v6);
  if is_v6 {
    // IPV6_RECVPKTINFO — destination address + interface index. Only where
    // libc defines IPV6_PKTINFO (`has_ipv6_pktinfo`).
    #[cfg(has_ipv6_pktinfo)]
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, on)?;
    // IPV6_RECVHOPLIMIT — hop limit, carried as a diagnostic and read by no
    // admission decision. Only where libc
    // defines the hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, on)?;
  } else {
    // IP_PKTINFO — destination address + interface index. Only where libc
    // defines the shared in_pktinfo layout (`has_ip_pktinfo`; BSDs excluded).
    #[cfg(has_ip_pktinfo)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, on)?;
    // IP_RECVDSTADDR + IP_RECVIF — the BSD spelling of those same two facts,
    // in two separate cmsgs (`has_ip_dstaddr_recvif`; the four BSDs, and
    // mutually exclusive with `has_ip_pktinfo` by construction in build.rs).
    //
    // FATAL, exactly like `IP_PKTINFO` above and for the same reason: setting
    // the cfg makes `rx_interface_reported` answer `true` for IPv4, which in
    // turn makes a missing interface witness REFUSE instead of admit. A
    // best-effort enable that silently failed would leave every datagram
    // witness-less on a path that has declared it can witness, and a responder
    // that is deaf on IPv4 while still looking healthy is worse than one that
    // fails to construct.
    #[cfg(has_ip_dstaddr_recvif)]
    {
      set_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, on)?;
      set_int(fd, libc::IPPROTO_IP, libc::IP_RECVIF, on)?;
    }
    // IP_RECVTTL — TTL, carried as a diagnostic and read by no admission
    // decision. Only where libc defines the
    // hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, on)?;
  }
  // SO_TIMESTAMP[NS] — kernel rx time for ordered self-send classification.
  // Family-agnostic (`SOL_SOCKET`); best-effort, and a socket without it simply
  // yields no evidence, degrading the self-send match rather than breaking it.
  // We ENABLE via the SO_* sockopt; the kernel then tags the received cmsg with
  // the matching SCM_* type, which `hick-udp` — not this crate — decodes out of
  // the control buffer (see `RxDatagram::from_recv_parts` in `Socket::recv`).
  // `recv_timestamp_ns` selects the nanosecond SO_TIMESTAMPNS (Linux/Android)
  // over the microsecond SO_TIMESTAMP; `hick-udp`'s matching cfg selects the
  // SCM_* type it looks for, and both crates emit that cfg from the same
  // build.rs matrix.
  #[cfg(all(has_recv_timestamp, recv_timestamp_ns))]
  set_int(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, on).ok();
  #[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
  set_int(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, on).ok();
  Ok(())
}

fn set_int(
  fd: std::os::fd::RawFd,
  level: libc::c_int,
  optname: libc::c_int,
  val: libc::c_int,
) -> std::io::Result<()> {
  // SAFETY: `&val` is a valid pointer to a `c_int`, passed with the matching length.
  let rc = unsafe {
    libc::setsockopt(
      fd,
      level,
      optname,
      &val as *const _ as *const _,
      core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if rc != 0 {
    Err(std::io::Error::last_os_error())
  } else {
    Ok(())
  }
}

/// Recover the BSD IPv4 destination and receive interface out of the
/// `IP_RECVDSTADDR` + `IP_RECVIF` cmsg pair, through **`hick-udp`'s parser** and
/// not a second reading of it.
///
/// # Why this is a delegated parse when the `IP_PKTINFO` arm is not
///
/// `IP_PKTINFO` is one cmsg carrying one fixed struct, and the arm below reads
/// three fields out of it. This pair is not that: the payloads are a bare
/// `struct in_addr` and a VARIABLE-LENGTH `struct sockaddr_dl` whose only
/// readable part is a `u_short` at a fixed offset, the two cmsgs are allocated
/// separately so either may arrive without the other, and the constants differ
/// per target — `IP_RECVIF` is 20 on FreeBSD/DragonFly/NetBSD and 30 on OpenBSD,
/// while `sockaddr_dl` has a different trailing shape and size on each of the
/// four. `hick_udp::parse_dstaddr_recvif_v4` already decodes exactly that, with
/// `const _` assertions pinning `offset_of!(sockaddr_dl, sdl_index)` against
/// `libc` for whichever BSD is compiled and unit tests over synthesized buffers
/// behind them. A hand-rolled copy here would be a second reading of one kernel
/// ABI — the cost this crate already stopped paying for `SCM_TIMESTAMP` — and
/// the four §11 gates disagreeing about what a control buffer says is the defect
/// this whole redesign exists to close.
///
/// The CAPABILITY answer stays this crate's own (see
/// [`super::rx_interface_reported`]); what is delegated is the byte decode.
///
/// # Only the halves the parser WITNESSED are taken, and this is the subtle part
///
/// The parser's VALUES are taken verbatim — a recovered address or index is
/// never re-derived here. Its ABSENCES are not taken at all, and must not be.
///
/// `parse_dstaddr_recvif_v4` is defined over a byte slice, so it cannot see
/// `msg_flags`. It spells every absence with `from_reporting_path(.., false)` —
/// a hardcoded "not truncated" — because [`hick_udp::onlink::DestinationWitness::Lost`]
/// accuses OUR control buffer and a parser has no way to know whether that
/// buffer overflowed. `Declined` is the only absence it can honestly return.
/// The caller DOES know: [`super::RecvMeta::declare_cmsg_absent`] has already
/// spelled both absences for this datagram from the kernel's own `MSG_CTRUNC`.
///
/// Copying both witnesses wholesale would therefore overwrite a correct `Lost`
/// with a wrong `Declined` on a PARTIAL pair under truncation — the two cmsgs
/// are allocated separately, so one can survive a truncation the other did not.
/// That downgrade turns REFUSE into DEGRADE on precisely the two squares this
/// capability exists to close: an absent interface would stop refusing group
/// traffic that arrived on another link, and an absent destination would reopen
/// the in-prefix broadcast admission. `Lost` accuses us, `Declined` says the
/// kernel answered and its answer named nothing — the distinction the whole
/// witness redesign is built around, erased at exactly the seam where the two
/// halves of the information meet.
///
/// So each half is taken only when it is `Witnessed`, and every absent half is
/// left as the caller declared it. No `control_truncated` parameter is needed
/// and none is taken: the flag is already encoded in the values this overwrites,
/// and a second reading of it here would be a second place to get it wrong.
///
/// **A `Witnessed` half is trustworthy even under `MSG_CTRUNC`.** `hick-udp`'s
/// `CmsgIter` bounds the walk by the slice — it ends the walk on a `cmsg_len`
/// that overruns and clips the payload to what is actually there — and
/// `decode_recvdstaddr` requires a full `in_addr` while `decode_recvif_index`
/// requires the full `sockaddr_dl` prefix. A partially-copied cmsg is short and
/// is rejected; it cannot present as `Witnessed`. So keeping it is not optimism,
/// and it is the same thing the `IP_PKTINFO` arm below has always done — that
/// arm decodes under truncation too and overwrites the predeclared witness when
/// a complete cmsg is present. Doing otherwise here would make one crate's two
/// IPv4 paths disagree about what `MSG_CTRUNC` means.
///
/// This is the one place this driver is deliberately MORE informative than
/// `hick_udp::recv_with_meta`, which returns `Lost` for both halves under
/// `MSG_CTRUNC` without parsing at all. The difference is only ever in the
/// admitting direction on a witness the kernel really did deliver — a complete
/// `IP_RECVDSTADDR` naming the mDNS group is local-link origin under §11 on its
/// own — so that path is being conservative rather than this one permissive.
/// Every ABSENCE is spelled identically by both.
///
/// `local_ip` is deliberately untouched. Neither cmsg carries an `ipi_spec_dst`
/// equivalent, so the receiving interface's own unicast address is simply absent
/// from the ancillary data on these platforms, and `RecvMeta::empty` already left
/// it UNSPECIFIED — which callers read as "fall back to content-hash self-detection".
///
/// # No address-family guard, on purpose
///
/// The cmsg LEVEL is the discriminator, exactly as it is for every arm below:
/// the parser matches `IPPROTO_IP` (0) and no cmsg a v6 socket receives carries
/// that level, so on a v6 receive this returns `Err` and changes nothing.
/// Running before the loop also means the `IPV6_PKTINFO` arm wins any
/// contradiction, which is the correct precedence for a socket that somehow saw
/// both.
#[cfg(has_ip_dstaddr_recvif)]
fn decode_bsd_ipv4_dstaddr_recvif(ctrl: &[u8], meta: &mut RecvMeta) {
  use hick_udp::onlink::{DestinationWitness, IfaceWitness};

  // `len` is only used to populate the parsed meta's own length field, which is
  // discarded here — this driver's length comes from `recv_msg`.
  let Ok(parsed) = hick_udp::parse_dstaddr_recvif_v4(ctrl, meta.len, meta.peer) else {
    return;
  };
  // `Witnessed` only. An absent half keeps whatever `declare_cmsg_absent` put
  // there, which is the only spelling that knows about `MSG_CTRUNC` — see this
  // function's doc for why taking the parser's absence instead downgrades
  // REFUSE to DEGRADE on a partial pair.
  //
  // THE INTERFACE HALF IS PROMOTED UNCONDITIONALLY. It can only ever REFUSE:
  // `arrived_on_bound_interface` runs before the destination arm and returns
  // `ForeignLink` when the index disagrees with the binding, so taking it can
  // only narrow what is admitted, never widen it.
  if let IfaceWitness::Witnessed(idx) = parsed.iface_witness() {
    meta.iface = IfaceWitness::Witnessed(idx);
  }
  // THE DESTINATION HALF IS PROMOTED THE SAME WAY, and on its own account: the
  // two cmsgs are decoded independently and each is taken whether or not the
  // other arrived.
  //
  // An earlier version of this function took the destination only WITH the
  // interface beside it, to keep §11 arm one's "regardless of source IP address"
  // exemption from being granted to a datagram nothing scoped to the bound link.
  // The goal was right and the mechanism was wrong: gating the PROMOTION erases
  // the address, and the address is what every NEGATIVE class is decided by.
  // Dropped here, a foreign multicast group stopped being refused as
  // `ForeignGroup` and fell to the coarse arms — admitted outright by `MSG_MCAST`
  // on OpenBSD/NetBSD, and admitted for any in-prefix sender on
  // FreeBSD/DragonFly. Withholding a privilege by destroying the evidence it
  // rests on gives away everything else that evidence was refusing.
  //
  // The rule now lives where both witnesses already meet:
  // `hick_onlink::admits_ingress` withholds the exemption from a datagram
  // nothing scoped and hands it §11's source arm, while every negative arm keeps
  // reading the address. It is stated over the WITNESS PAIR rather than over a
  // cmsg shape, so it also covers the `IP_PKTINFO` square below — one cmsg, one
  // zero `ipi_ifindex`, the same pair — which a rule written here could not
  // reach and did not.
  if let DestinationWitness::Witnessed(dst) = parsed.destination_witness() {
    meta.destination = DestinationWitness::Witnessed(dst);
  }
}

pub(super) fn decode_unix_cmsgs(ctrl: &[u8], meta: &mut RecvMeta, control_truncated: bool) {
  // `ctrl` originates from `AlignedCtrlBuf::filled`, whose storage is the
  // start of a `#[repr(align(8))]` array — so the slice's first byte is
  // aligned for `cmsghdr`. Defensive bail for the rare future caller that
  // doesn't honour that invariant.
  if ctrl.is_empty() {
    return;
  }
  if !ctrl.as_ptr().cast::<libc::cmsghdr>().is_aligned() {
    return;
  }
  #[cfg(has_ip_dstaddr_recvif)]
  decode_bsd_ipv4_dstaddr_recvif(ctrl, meta);
  for c in CMsgIter::new(ctrl) {
    match (c.level(), c.ty()) {
      // IPv4 PKTINFO — only where libc defines the shared in_pktinfo layout
      // (`has_ip_pktinfo`; BSDs excluded — see build.rs).
      #[cfg(has_ip_pktinfo)]
      (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
        if c.data_len() < core::mem::size_of::<libc::in_pktinfo>() {
          continue;
        }
        // SAFETY: kernel writes `in_pktinfo` for the `IP_PKTINFO` cmsg, and the
        // length guard above ensures the cmsg carries at least
        // `size_of::<in_pktinfo>()` payload bytes before this read. CMSG_DATA
        // is only `cmsghdr`-aligned, so use `read_unaligned`.
        let pi = unsafe { core::ptr::read_unaligned(c.data::<libc::in_pktinfo>()) };
        meta.local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(pi.ipi_spec_dst.s_addr)));
        // `ipi_addr` is the IP header DESTINATION — the group, for a multicast
        // arrival — while `ipi_spec_dst` above is the receiving interface's own
        // unicast address. RFC 6762 §11 selects its local-link test by the
        // former; reading the latter made every multicast arrival look unicast
        // and sent it to the source-prefix arm, which refuses an on-link peer
        // sourcing from a prefix this interface does not carry.
        meta.destination = DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::from(u32::from_be(
          pi.ipi_addr.s_addr,
        ))));
        // A zero `ipi_ifindex` INSIDE a present cmsg is a kernel that named no
        // interface, not a path that cannot name one — `from_reporting_path`
        // makes that `Declined`, or `Lost` where our own buffer truncated. The
        // C field is `int` (`c_int` in `libc` on Linux and Android, `c_uint` on
        // Apple), so it goes through the SIGNED constructor, where a negative
        // is that same absence and never an index near `u32::MAX`.
        meta.iface =
          IfaceWitness::from_reporting_path_signed(pi.ipi_ifindex as i32, control_truncated);
      }
      // IPv6 PKTINFO — only where libc defines IPV6_PKTINFO (`has_ipv6_pktinfo`).
      #[cfg(has_ipv6_pktinfo)]
      (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
        if c.data_len() < core::mem::size_of::<libc::in6_pktinfo>() {
          continue;
        }
        // SAFETY: kernel writes `in6_pktinfo` for the `IPV6_PKTINFO` cmsg, and
        // the length guard above ensures the payload is at least
        // `size_of::<in6_pktinfo>()` bytes before this read.
        let pi = unsafe { core::ptr::read_unaligned(c.data::<libc::in6_pktinfo>()) };
        // IPv6 PKTINFO carries only the header destination — there is no
        // `ipi_spec_dst` twin — so the one address serves as both.
        meta.local_ip = IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr));
        meta.destination =
          DestinationWitness::Witnessed(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr)));
        // `libc` types `ipi6_ifindex` as `c_int` on Android and `c_uint` on
        // every other supported unix, though the Linux uapi header declares it
        // `int` there too. The `as i32` normalises both onto the signed
        // constructor, where a negative is an absence rather than an index near
        // `u32::MAX`.
        meta.iface =
          IfaceWitness::from_reporting_path_signed(pi.ipi6_ifindex as i32, control_truncated);
      }
      // IPv4 TTL — only where libc defines the hop-limit cmsg constants
      // (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
      #[cfg(has_recv_hoplimit)]
      (libc::IPPROTO_IP, libc::IP_TTL) | (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
        if c.data_len() < core::mem::size_of::<libc::c_int>() {
          continue;
        }
        // SAFETY: kernel writes a `c_int` for `IP_TTL` / `IP_RECVTTL`, and the
        // length guard above ensures at least `size_of::<c_int>()` payload
        // bytes are present before this read.
        let v = unsafe { core::ptr::read_unaligned(c.data::<libc::c_int>()) };
        meta.hop_limit = Some(v as u8);
      }
      // IPv6 Hop Limit — same `has_recv_hoplimit` gate as the IPv4 TTL arm.
      #[cfg(has_recv_hoplimit)]
      (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
        if c.data_len() < core::mem::size_of::<libc::c_int>() {
          continue;
        }
        // SAFETY: kernel writes a `c_int` for `IPV6_HOPLIMIT`, and the length
        // guard above ensures at least `size_of::<c_int>()` payload bytes are
        // present before this read.
        let v = unsafe { core::ptr::read_unaligned(c.data::<libc::c_int>()) };
        meta.hop_limit = Some(v as u8);
      }
      // The kernel receive-timestamp cmsg is deliberately NOT decoded here.
      // `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` is one wire format, `hick-udp` already
      // reads it, and `Socket::recv` hands it this same buffer through
      // `RxDatagram::from_recv_parts`. Two readings of one kernel ABI drift
      // silently — a wrong stamp still type-checks — and that is the cost this
      // crate stopped paying. It does NOT make the resulting evidence checkable:
      // that is still a caller contract, discharged at the mint's call site.
      // An arm added back here would re-take the cost and buy nothing — and it
      // now has nowhere to put what it decodes, since `RecvMeta` carries no
      // stamp field at all.
      _ => {}
    }
  }
}

/// Regression for the family-blind cmsg setup: `enable_recv_cmsgs` used to
/// apply the IPv4-only `IP_PKTINFO` / `IP_RECVTTL` sockopts with a fatal `?`
/// to EVERY socket, so an `AF_INET6` socket failed with `EINVAL` and
/// `from_std` bubbled the error — breaking v6-only and dual-stack endpoint
/// construction before any datagram could flow. `from_std` must now succeed on
/// a v6 socket by applying only the v6 cmsg options.
#[cfg(all(unix, test))]
#[compio::test]
async fn from_std_enables_cmsgs_on_v6_socket() {
  use crate::socket::Socket;
  use std::net::{Ipv6Addr, UdpSocket};

  let sock = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
    Ok(s) => s,
    Err(_) => return, // host without usable IPv6 — environmental skip
  };
  let wrapped = Socket::from_std(sock).await;
  assert!(
    wrapped.is_ok(),
    "from_std must enable cmsgs on a v6 socket without EINVAL, got {:?}",
    wrapped.err()
  );
}

/// Companion to [`from_std_enables_cmsgs_on_v6_socket`]: the per-family gating
/// must not regress the v4 path.
#[cfg(all(unix, test))]
#[compio::test]
async fn from_std_enables_cmsgs_on_v4_socket() {
  use crate::socket::Socket;
  use std::net::{Ipv4Addr, UdpSocket};

  let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind v4");
  let wrapped = Socket::from_std(sock).await;
  assert!(
    wrapped.is_ok(),
    "from_std must still succeed on a v4 socket, got {:?}",
    wrapped.err()
  );
}

/// The kernel receive-timestamp payload as a **byte image**: `libc::timespec`
/// on Linux/Android, `libc::timeval` on Apple/BSD, with every byte initialized.
///
/// Assembled field by field at each `core::mem::offset_of!` position inside a
/// zeroed buffer; the struct never exists as a value at all. That is a
/// soundness requirement rather than a style choice. On Apple/aarch64
/// `libc::timeval` is `{ time_t, suseconds_t }` — 12 bytes of fields in a
/// 16-byte type — so a struct literal leaves four TAIL-PADDING bytes
/// uninitialized, and any *typed* store of such a value (`write_unaligned::<T>`,
/// which is what [`CMsgBuilder::push`] does) carries that uninitializedness into
/// the control buffer. Reading the encoded range back as `&[u8]` is then
/// undefined behaviour.
///
/// **Zeroing the destination first does not help.** A typed copy does not
/// preserve padding initializedness, so the padding is de-initialized again
/// whatever the destination held — which is exactly why the fix is to keep the
/// padded struct out of the typed path rather than to prepare the buffer for it.
///
/// # Which targets actually pad, measured rather than assumed
///
/// It is not an Apple quirk and it is not the whole `timeval` family either, so
/// neither "it is only Darwin" nor "it is only `timeval`" is a safe shortcut:
///
/// * `aarch64-apple-darwin` — `timeval` **pads**, 12 bytes of fields in 16
///   (`suseconds_t` is `i32` beside an `i64` `time_t`);
/// * `x86_64-unknown-netbsd` — `timeval` **pads**, for the same reason;
/// * `x86_64-unknown-freebsd` — `timeval` does NOT pad; `suseconds_t` is 8 bytes
///   there, so the fields tile the struct;
/// * `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-musl` — `timespec` does
///   NOT pad, two 8-byte fields in 16.
///
/// This construction does not consult that table — it is padding-correct either
/// way, which is the point of writing at `offset_of!` into zeroed bytes rather
/// than reasoning per target. The table is here so a future reader knows the
/// hazard is real on more than one supported target, and
/// `timestamp_payload_padding_is_measured_not_assumed` keeps the numbers honest
/// on whatever target actually runs.
#[cfg(all(unix, has_recv_timestamp, test))]
fn ts_payload_bytes(secs: i64, sub: i64) -> Vec<u8> {
  #[cfg(recv_timestamp_ns)]
  use libc::timespec as TsPayload;
  #[cfg(not(recv_timestamp_ns))]
  use libc::timeval as TsPayload;

  let mut buf = vec![0u8; core::mem::size_of::<TsPayload>()];
  {
    let mut put = |offset: usize, bytes: &[u8]| {
      buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    put(
      core::mem::offset_of!(TsPayload, tv_sec),
      &(secs as libc::time_t).to_ne_bytes(),
    );
    #[cfg(recv_timestamp_ns)]
    put(
      core::mem::offset_of!(TsPayload, tv_nsec),
      &(sub as libc::c_long).to_ne_bytes(),
    );
    #[cfg(not(recv_timestamp_ns))]
    put(
      core::mem::offset_of!(TsPayload, tv_usec),
      &(sub as libc::suseconds_t).to_ne_bytes(),
    );
  }
  buf
}

/// Which of the two layouts this target uses, and whether it has tail padding —
/// measured rather than assumed, because the whole padding defect turns on it
/// and a target that quietly grew padding would otherwise re-open it silently.
///
/// This asserts nothing about *which* answer is right: [`ts_payload_bytes`] is
/// correct either way. It exists so the answer is on the record per target — on
/// Apple/aarch64 `timeval` is 16 bytes over 12 bytes of fields (4 padding) while
/// `timespec` is 16 over 16 (none).
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn timestamp_payload_padding_is_measured_not_assumed() {
  #[cfg(not(recv_timestamp_ns))]
  let (name, size, fields) = (
    "timeval",
    core::mem::size_of::<libc::timeval>(),
    core::mem::size_of::<libc::time_t>() + core::mem::size_of::<libc::suseconds_t>(),
  );
  #[cfg(recv_timestamp_ns)]
  let (name, size, fields) = (
    "timespec",
    core::mem::size_of::<libc::timespec>(),
    core::mem::size_of::<libc::time_t>() + core::mem::size_of::<libc::c_long>(),
  );
  assert!(
    fields <= size,
    "{name}: fields ({fields}) cannot exceed the struct ({size})"
  );
  // The byte image must cover the WHOLE struct, padding included, or the bytes
  // handed to `push_bytes` would be short of `CMSG_LEN`'s payload length.
  assert_eq!(
    ts_payload_bytes(1, 2).len(),
    size,
    "{name}: the byte image must span the struct, not just its fields"
  );
  println!(
    "{name}: size={size} fields={fields} padding={}",
    size - fields
  );
}

/// Build a minimal control buffer containing a single SOL_SOCKET receive-
/// timestamp cmsg (the SCM_* TYPE the kernel actually delivers — and that
/// `decode_unix_cmsgs` matches), then iterate it and verify level/type/data.
/// The constant + payload are chosen by `recv_timestamp_ns`: nanosecond
/// SCM_TIMESTAMPNS/timespec on Linux/Android, microsecond SCM_TIMESTAMP/timeval
/// on Apple/BSD.
///
/// The buffer is built by hand rather than through [`CMsgBuilder`] on purpose:
/// this is `CMsgIter`'s test, and routing it through the builder would make the
/// two halves of one round trip prove each other. What it does share is
/// [`ts_payload_bytes`] — the payload goes in as an initialized byte image and
/// is copied byte-to-byte, never stored as a padded struct value.
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn cmsg_iter_walks_a_single_timestamp_cmsg() {
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};
  use libc::{SOL_SOCKET, cmsghdr};
  let payload = ts_payload_bytes(1234, 56);
  let payload_bytes = payload.len();
  assert_eq!(payload_bytes, core::mem::size_of::<TsPayload>());
  let total = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
  // Use a u64-backed allocation to guarantee at least 8-byte alignment,
  // which covers every cmsghdr alignment on supported targets. A plain
  // `vec![0u8; total]` is only alignment 1 and would trip CMsgIter::new.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let words = total.div_ceil(core::mem::size_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; words.max(1)];
  // SAFETY: backing owns `words * 8` zeroed bytes; `total <= words * 8`,
  // so the resulting slice fits inside the allocation. The bytes stay
  // borrowed for the lifetime of this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
  // SAFETY: buf is correctly sized and zero-initialised; we write a valid
  // cmsghdr. The header pointer is aligned (Vec<u64> backing). Its fields are
  // assigned INDIVIDUALLY, never by storing a whole `cmsghdr` value, so the
  // header's own padding (musl's `__pad1`) keeps the zeroes above. The payload
  // is a byte-to-byte `copy_nonoverlapping` out of an initialized slice, which
  // needs no alignment and — unlike the `write_unaligned::<TsPayload>` this
  // replaced — cannot de-initialize the struct's tail padding. See
  // `ts_payload_bytes`.
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
    (*hdr).cmsg_level = SOL_SOCKET;
    (*hdr).cmsg_type = TS_TYPE;
    let data = libc::CMSG_DATA(hdr);
    core::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload_bytes);
  }
  // Every encoded byte must be genuinely INITIALIZED, not merely zero. Only a
  // real per-byte read asserts that: the walk below reads the header fields and
  // then the payload as a typed `TsPayload`, and a typed read does not require
  // padding to be initialized — so without this loop the uninitialized-padding
  // regression is invisible here. Under Miri this is the regression test; in a
  // normal build it is a cheap checksum.
  let mut acc: u64 = 0;
  for b in buf.iter() {
    acc = acc.wrapping_add(u64::from(*b));
  }
  assert!(acc > 0, "the encoded cmsg must not be all-zero");
  let mut iter = CMsgIter::new(buf);
  let first = iter.next().expect("one cmsg");
  assert_eq!(first.level(), SOL_SOCKET);
  assert_eq!(first.ty(), TS_TYPE);
  // CMSG_DATA is only guaranteed to satisfy cmsghdr's alignment, not the
  // payload type's. On macOS `cmsghdr` is 4-byte aligned and `timeval`
  // wants 8 — read unaligned to stay sound across all targets.
  let got = unsafe { core::ptr::read_unaligned(first.data::<TsPayload>()) };
  assert_eq!(got.tv_sec, 1234);
  #[cfg(recv_timestamp_ns)]
  assert_eq!(got.tv_nsec, 56);
  #[cfg(not(recv_timestamp_ns))]
  assert_eq!(got.tv_usec, 56);
  assert!(iter.next().is_none(), "no second cmsg");
}

/// Round-trip an `IP_PKTINFO` cmsg through `CMsgBuilder` and `CMsgIter`:
/// the builder encodes the header + payload, then the iterator must read
/// back the same level/type/payload.
///
/// `has_ip_pktinfo`-gated: `IP_PKTINFO`/`in_pktinfo` are only bound where
/// `build.rs` sets that cfg (Linux/Android/Apple); the BSDs have no
/// `IP_PKTINFO` (NetBSD's `in_pktinfo` is a different, incompatible shape —
/// see `build.rs`), so a bare `#[cfg(all(unix, test))]` here fails to link
/// the import on FreeBSD/OpenBSD/DragonFly/NetBSD.
#[cfg(all(unix, has_ip_pktinfo, test))]
#[test]
fn cmsg_builder_emits_a_round_trippable_pktinfo() {
  use libc::{IP_PKTINFO, IPPROTO_IP, in_addr, in_pktinfo};
  let pktinfo = in_pktinfo {
    ipi_ifindex: 7,
    ipi_spec_dst: in_addr {
      s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
    },
    ipi_addr: in_addr {
      s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
    },
  };
  // `vec![0u8; 128]` is only alignment 1, which would trip CMsgIter::new's
  // alignment assert. Back the buffer with a
  // `Vec<u64>` to get ≥8-byte alignment for the underlying bytes.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; 128 / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `len * 8 == 128` zeroed bytes; the resulting slice
  // is borrowed for the rest of this scope and never aliased.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), 128) };
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push(IPPROTO_IP, IP_PKTINFO, &pktinfo).expect("fits");
    b.finish()
  };
  assert!(written > 0);
  let mut iter = CMsgIter::new(&buf[..written]);
  let cmsg = iter.next().expect("round-tripped one cmsg");
  assert_eq!(cmsg.level(), IPPROTO_IP);
  assert_eq!(cmsg.ty(), IP_PKTINFO);
  // CMSG_DATA is only guaranteed to satisfy cmsghdr's alignment; on macOS
  // `cmsghdr` aligns to 4, and `in_pktinfo` also aligns to 4, so this is
  // fine in practice — but use `read_unaligned` defensively to mirror the
  // builder's `write_unaligned`.
  let got = unsafe { core::ptr::read_unaligned(cmsg.data::<in_pktinfo>()) };
  assert_eq!(got.ipi_ifindex, 7);
  assert!(iter.next().is_none(), "no second cmsg");
}

/// Read the payload of EVERY cmsg in a two-entry buffer, second one included.
///
/// This is the provenance test, and it is deliberately not covered by the
/// single-cmsg tests above. [`CMsgRef::data`] returns a pointer derived from
/// the header pointer [`CMsgIter`] minted, and the two headers are minted by
/// different routes: the first is the walk's starting offset and would be right
/// even if the stride arithmetic were not, while the second is the one
/// [`CMsgIter::successor`] has to compute. A `CMsgRef` that held a `&cmsghdr`
/// narrowed that pointer's provenance to the header, making the payload read
/// out of bounds for its own tag on BOTH of them. Neither property is
/// observable in a normal build — `cargo miri test -p hick-compio
/// --lib` is where this test does its work.
///
/// The payload type is `u32` and the levels/types are arbitrary: `CMsgIter`
/// walks by `cmsg_len` alone and never interprets either field, so nothing here
/// needs a platform capability cfg, and this runs on every unix target.
#[cfg(all(unix, test))]
#[test]
fn cmsg_iter_reads_the_payload_of_every_cmsg_it_walks() {
  const FIRST: (libc::c_int, libc::c_int) = (libc::SOL_SOCKET, 0x11);
  const SECOND: (libc::c_int, libc::c_int) = (libc::SOL_SOCKET, 0x22);
  // `Vec<u64>` backing for ≥8-byte alignment, as in the tests above; a plain
  // `vec![0u8; N]` is alignment 1 and would trip `CMsgIter::new`.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; 128 / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `len * 8 == 128` zeroed bytes; the resulting slice is
  // borrowed for the rest of this scope and never aliased.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), 128) };
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push(FIRST.0, FIRST.1, &0xa1a2_a3a4u32)
      .expect("first fits");
    b.push(SECOND.0, SECOND.1, &0xb1b2_b3b4u32)
      .expect("second fits");
    b.finish()
  };
  let walked: Vec<(libc::c_int, libc::c_int, u32)> = CMsgIter::new(&buf[..written])
    .map(|c| {
      assert!(
        c.data_len() >= core::mem::size_of::<u32>(),
        "the builder wrote a full u32 payload"
      );
      // CMSG_DATA guarantees only `cmsghdr` alignment, so read unaligned —
      // the same rule `CMsgRef::data` documents for `timeval`/`timespec`.
      let v = unsafe { core::ptr::read_unaligned(c.data::<u32>()) };
      (c.level(), c.ty(), v)
    })
    .collect();
  assert_eq!(
    walked,
    vec![
      (FIRST.0, FIRST.1, 0xa1a2_a3a4u32),
      (SECOND.0, SECOND.1, 0xb1b2_b3b4u32),
    ],
    "both cmsgs must round-trip, the second through the computed stride"
  );
}

/// A `cmsghdr`-aligned scratch buffer plus the number of bytes a builder wrote
/// into it, for the malformed-input tests below. Mirrors `AlignedCtrlBuf`'s
/// shape — a fixed backing array, of which only a prefix is ever presented —
/// because that is what makes the truncation test faithful AND detectable: the
/// slice handed to `CMsgIter` is a PREFIX of a larger live allocation, exactly
/// as `AlignedCtrlBuf::filled(kernel_len)` produces, so a read past the prefix
/// is out of bounds for the slice's tag while still landing on readable memory.
/// A test that instead sized the allocation to the prefix would catch the same
/// bug for the wrong reason, and would stop catching it the moment the
/// production buffer went back to being fixed-size.
#[cfg(all(unix, test))]
struct CtrlScratch {
  backing: Vec<u64>,
}

#[cfg(all(unix, test))]
impl CtrlScratch {
  const BYTES: usize = 128;

  fn new() -> Self {
    assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
    Self {
      backing: vec![0u64; Self::BYTES / core::mem::size_of::<u64>()],
    }
  }

  /// The whole scratch area as bytes.
  fn bytes(&mut self) -> &mut [u8] {
    // SAFETY: `backing` owns `len * 8 == BYTES` initialised bytes, and the
    // slice borrows it for no longer than `self`.
    unsafe { core::slice::from_raw_parts_mut(self.backing.as_mut_ptr().cast::<u8>(), Self::BYTES) }
  }

  /// The first `n` bytes, as a kernel-filled control buffer of length `n`.
  fn filled(&self, n: usize) -> &[u8] {
    assert!(n <= Self::BYTES);
    // SAFETY: as in `bytes`, narrowed to `n <= BYTES`.
    unsafe { core::slice::from_raw_parts(self.backing.as_ptr().cast::<u8>(), n) }
  }
}

/// A final cmsg whose `cmsg_len` claims more bytes than the control buffer
/// holds must not be yielded — and the well-formed cmsg in front of it must
/// still be.
///
/// This is the `MSG_CTRUNC` shape, and it is the kernel's normal behaviour
/// rather than a corrupt-input hypothetical: on Darwin a truncated receive
/// copies a PREFIX of the last cmsg and leaves its original `cmsg_len` in
/// place. An iterator that reports `data_len()` straight off that field passes
/// the caller-side `data_len() >= size_of::<T>()` guard and then reads past the
/// end of the buffer — which is what `decode_unix_cmsgs` does, verbatim, in the
/// loop below.
///
/// Under Miri the read is a hard error. In a normal build it is silent, which
/// is the whole reason this test reads the payload rather than merely asserting
/// on `data_len()`: an assertion on the length alone would go green on a build
/// where the length is wrong AND the read runs off the end.
#[cfg(all(unix, test))]
#[test]
fn a_cmsg_claiming_more_than_the_buffer_holds_is_refused_and_its_predecessor_kept() {
  const KEPT: (libc::c_int, libc::c_int) = (libc::SOL_SOCKET, 0x31);
  const TRUNCATED: (libc::c_int, libc::c_int) = (libc::SOL_SOCKET, 0x32);
  // Both payloads are `u64` so the SAME guard-and-read covers both cmsgs: the
  // survivor is genuinely read back, and the truncated one — if it were
  // yielded — would be read past the end of the buffer rather than merely
  // reported with a wrong length.
  let payload = core::mem::size_of::<u64>();
  let mut scratch = CtrlScratch::new();
  let written = {
    let buf = scratch.bytes();
    let mut b = CMsgBuilder::new(buf);
    b.push(KEPT.0, KEPT.1, &0xc1c2_c3c4_c5c6_c7c8u64)
      .expect("first fits");
    b.push(TRUNCATED.0, TRUNCATED.1, &0xd1d2_d3d4_d5d6_d7d8u64)
      .expect("second fits");
    b.finish()
  };
  // SAFETY: CMSG_SPACE is pure length arithmetic over an integer.
  let first_end = unsafe { libc::CMSG_SPACE(payload as u32) } as usize;
  // Chop the tail of the SECOND cmsg's payload while leaving its header — and
  // its `cmsg_len` — intact, which is precisely what MSG_CTRUNC delivers.
  let kernel_len = written - payload / 2;
  assert!(
    kernel_len > first_end + core::mem::size_of::<cmsghdr>(),
    "the truncation must leave the second header addressable, or the test \
     degenerates into the ordinary end-of-buffer case"
  );
  let ctrl = scratch.filled(kernel_len);

  let mut seen = Vec::new();
  for c in CMsgIter::new(ctrl) {
    // Exactly `decode_unix_cmsgs`'s guard-then-read shape.
    assert!(
      c.data_len() >= payload,
      "every cmsg this walk yields must carry a payload the buffer backs"
    );
    let v = unsafe { core::ptr::read_unaligned(c.data::<u64>()) };
    seen.push((c.level(), c.ty(), v));
  }
  assert_eq!(
    seen,
    vec![(KEPT.0, KEPT.1, 0xc1c2_c3c4_c5c6_c7c8u64)],
    "the intact cmsg must survive and the truncated one must not be yielded"
  );
}

/// A control buffer whose FINAL cmsg's successor lands exactly at `len`, and
/// one where it lands past `len`, must both walk to completion.
///
/// This is the case libc's Android `CMSG_NXTHDR` makes undefined. It evaluates
///
/// ```text
/// let next = (cmsg as usize + CMSG_ALIGN((*cmsg).cmsg_len as usize)) as *mut cmsghdr;
/// let max  = (*mhdr).msg_control as usize + (*mhdr).msg_controllen as usize;
/// if (next.offset(1)) as usize > max { ... }
/// ```
///
/// — `libc-0.2.189`, `src/unix/linux_like/android/mod.rs:3468`. The `offset(1)`
/// forms a pointer one whole `cmsghdr` PAST `next` in order to decide whether
/// `next` was in range, so when `next` is the end of the allocation the pointer
/// is already out of bounds by the time libc returns anything to check. That is
/// reachable with WELL-FORMED ancillary data in a full control buffer, which is
/// why the buffer below is packed to its last byte rather than corrupted.
///
/// The allocation is sized EXACTLY to the bytes presented, so the final
/// successor is the end of the allocation and not merely the end of a slice:
/// pointer `offset` is bounds-checked against the allocation, so a prefix of a
/// larger buffer would hide the very thing this test exists to catch.
///
/// Run under `cargo miri test --target aarch64-linux-android`; on every other
/// target it still asserts the walk's arithmetic, which is stated over all of
/// them.
#[cfg(all(unix, test))]
#[test]
fn a_control_buffer_packed_to_its_last_byte_walks_to_completion() {
  let hdr_size = core::mem::size_of::<cmsghdr>();
  let payload = 12usize;
  // SAFETY: CMSG_LEN/CMSG_SPACE are pure length arithmetic over integers.
  let data_start = unsafe { libc::CMSG_LEN(0) } as usize;
  let cmsg_len = data_start + payload;
  // SAFETY: as above.
  let stride = unsafe { libc::CMSG_SPACE(payload as u32) } as usize;
  assert!(stride >= cmsg_len, "a stride must clear its own cmsg");
  // `count` is chosen so the total is a multiple of 8 and `vec![0u64; n]`
  // allocates EXACTLY the presented byte count — Darwin's cmsg alignment is 4,
  // so one stride need not be 8-aligned on its own.
  let word = core::mem::size_of::<u64>();
  let count = if stride.is_multiple_of(word) { 1 } else { 2 };
  let packed = stride * count;
  assert_eq!(
    packed % word,
    0,
    "the packed total must size a Vec<u64> exactly"
  );

  // Two shapes, differing only in how many bytes are presented:
  //   `packed`                        — the successor lands EXACTLY at len;
  //   `packed - (stride - cmsg_len)`  — the final cmsg's declared bytes end at
  //                                     len while its padded successor is past.
  for total in [packed, packed - (stride - cmsg_len)] {
    let words = total.div_ceil(word);
    let mut backing: Vec<u64> = vec![0u64; words];
    {
      // SAFETY: `backing` owns `words * 8 >= total` initialised bytes.
      let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
      for i in 0..count {
        let at = i * stride;
        if at + hdr_size > total {
          break;
        }
        // SAFETY: the bound above keeps the whole header inside `buf`, and the
        // `Vec<u64>` backing satisfies `cmsghdr` alignment. Fields are assigned
        // individually so the header's own padding keeps its zeroes.
        unsafe {
          let h = buf.as_mut_ptr().add(at).cast::<cmsghdr>();
          (&raw mut (*h).cmsg_len).write_unaligned(cmsg_len.min(total - at) as _);
          (&raw mut (*h).cmsg_level).write_unaligned(libc::SOL_SOCKET);
          (&raw mut (*h).cmsg_type).write_unaligned(0x51);
        }
      }
    }
    // SAFETY: as above, read-only and narrowed to the presented length.
    let ctrl: &[u8] = unsafe { core::slice::from_raw_parts(backing.as_ptr().cast::<u8>(), total) };
    let walked = CMsgIter::new(ctrl).take(64).count();
    assert!(
      walked <= count,
      "a buffer of {total} bytes holding at most {count} cmsg(s) must not yield \
       {walked} (stride={stride}, cmsg_len={cmsg_len})"
    );
  }
}

/// A `cmsg_len` that libc's own successor arithmetic cannot advance past must
/// end the walk, not repeat the header for ever.
///
/// `CMSG_NXTHDR` on Darwin and the BSDs is `cmsg + CMSG_ALIGN(cmsg_len)`, which
/// for `cmsg_len == 0` is `cmsg` — the same header, returned indefinitely, so a
/// walk that trusts it never terminates and `decode_unix_cmsgs` never returns.
/// Linux's copy rejects a `cmsg_len` below the header size and returns null
/// instead, so the non-termination is real on some supported targets and not
/// others; the fix (require strict forward progress) is stated over all of
/// them, and so is this test.
///
/// `take` bounds the walk so that a REGRESSION FAILS THIS TEST INSTEAD OF
/// HANGING IT. A hang is not evidence — it is indistinguishable from a slow
/// machine in CI, and it takes the whole test binary with it.
#[cfg(all(unix, test))]
#[test]
fn a_cmsg_length_that_cannot_advance_the_walk_ends_it() {
  let hdr_size = core::mem::size_of::<cmsghdr>();
  for bad_len in [0usize, 1, hdr_size - 1] {
    let mut scratch = CtrlScratch::new();
    let total = {
      let buf = scratch.bytes();
      let mut b = CMsgBuilder::new(buf);
      b.push(libc::SOL_SOCKET, 0x41, &0u32).expect("fits");
      let total = b.finish();
      // Overwrite only `cmsg_len`, leaving a structurally valid header —
      // assigned through a field projection so the header's own padding
      // (musl's `__pad1`) keeps the builder's zeroes.
      // SAFETY: `CMsgBuilder::new` asserted the buffer's `cmsghdr` alignment
      // and wrote a header at offset 0, so this addresses that header's own
      // `cmsg_len` field.
      unsafe {
        let hdr = buf.as_mut_ptr().cast::<cmsghdr>();
        (&raw mut (*hdr).cmsg_len).write_unaligned(bad_len as _);
      }
      total
    };
    let ctrl = scratch.filled(total);
    let yielded = CMsgIter::new(ctrl).take(64).count();
    assert_eq!(
      yielded, 0,
      "a cmsg_len of {bad_len} covers no header: the walk must fuse, not \
       yield (and on Darwin/BSD, not repeat this header for ever)"
    );
  }
}

/// A cmsg that advertises `IPPROTO_IP` / `IP_PKTINFO` but whose `cmsg_len`
/// only covers 2 payload bytes (far short of `in_pktinfo`) must be skipped,
/// not read: reading `in_pktinfo` out of it would run past the bytes the
/// kernel deposited. `decode_unix_cmsgs` must return without panicking and
/// leave `local_ip` / `interface_index` at their `RecvMeta::empty` defaults.
///
/// `has_ip_pktinfo`-gated: same reason as
/// [`cmsg_builder_emits_a_round_trippable_pktinfo`] — `IP_PKTINFO`/`in_pktinfo`
/// are unbound on the BSDs.
#[cfg(all(unix, has_ip_pktinfo, test))]
#[test]
fn truncated_pktinfo_cmsg_is_skipped_not_read() {
  use libc::{IP_PKTINFO, IPPROTO_IP, cmsghdr};
  // Reserve room for a full `in_pktinfo` payload so the buffer itself is
  // large enough; only `cmsg_len` is shrunk to claim a 2-byte payload, which
  // is what makes the cmsg "truncated" from the decoder's point of view.
  let payload_bytes = core::mem::size_of::<libc::in_pktinfo>();
  let total = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
  // Back with a `Vec<u64>` for ≥8-byte alignment, mirroring the iterator
  // tests above; a plain `vec![0u8; total]` is only alignment 1 and would
  // trip `decode_unix_cmsgs`'s alignment guard / `CMsgIter::new`.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let words = total.div_ceil(core::mem::size_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; words.max(1)];
  // SAFETY: backing owns `words * 8 >= total` zeroed bytes; the slice fits
  // inside the allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
  // SAFETY: buf is sized for a full `in_pktinfo` cmsg and zero-initialised;
  // we write a valid header but set `cmsg_len = CMSG_LEN(2)` so the cmsg
  // claims only 2 payload bytes.
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(2) as _;
    (*hdr).cmsg_level = IPPROTO_IP;
    (*hdr).cmsg_type = IP_PKTINFO;
  }
  let mut meta = RecvMeta::empty(([0u8, 0, 0, 0], 0).into());
  decode_unix_cmsgs(buf, &mut meta, false);
  // Left at defaults: the truncated cmsg was skipped, never read as garbage.
  assert!(
    meta.local_ip.is_unspecified(),
    "truncated PKTINFO populated local_ip from a short cmsg"
  );
  assert_eq!(
    meta.iface.index_or_zero(),
    0,
    "truncated PKTINFO populated the interface witness from a short cmsg"
  );
}

/// The receive-timestamp cmsg is `hick-udp`'s to read, and this crate must not
/// grow a second reading of it.
///
/// **One half of that is now structural rather than asserted.** `RecvMeta` has
/// no field a stamp can land in: the stamp travels inside the `RxDatagram` that
/// `Socket::recv` mints beside the body it belongs to, and there is no accessor
/// to read it back out. A decoder arm added here has nowhere to put what it
/// decodes, which is a stronger statement than the equality this test used to
/// make about `RecvMeta::rx`.
///
/// What is left needs asserting, and it is the half that fails silently: a
/// `Socket::recv` that stopped routing its control buffer through
/// `RxDatagram::from_recv_parts` would leave this driver claiming every
/// self-send on `Degraded` evidence forever, and nothing else would say so. The
/// stamp is observable only through the STRENGTH a claim runs at, so that is
/// what this measures — the same bytes, minted both ways, against one credit.
///
/// Malformed and absurd payloads are not retried here. That parser has one
/// implementation now and `hick-udp` tests it against `i64::MAX` in both
/// fields; re-proving it from this side is the duplication this change removed.
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn timestamp_cmsg_is_decoded_by_hick_udp_and_not_by_this_crate() {
  use std::time::{Duration, Instant as StdInstant, SystemTime};

  use hick_udp::{
    Family,
    selfsend::{ClockPair, RxDatagram, SelfSendMatch, SelfSendTracker},
  };
  use libc::{SOL_SOCKET, cmsghdr};

  // The SCM_* TYPE the kernel delivers, selected by `recv_timestamp_ns` exactly
  // as `hick-udp`'s parser selects the type it looks for — both cfgs come from
  // the same build.rs matrix, which is what keeps the two crates in step.
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};

  // The payload goes in as an initialized BYTE IMAGE and never exists as a
  // padded `TsPayload` value — see `ts_payload_bytes` for why that is a
  // soundness requirement rather than a style choice, and `push_bytes` for why
  // the builder needs a second path to accept it. Both assertions below read the
  // encoded range as `&[u8]`, which is undefined behaviour over an
  // uninitialized byte.
  let payload = ts_payload_bytes(1_700_000_000, 123_456);
  assert_eq!(payload.len(), core::mem::size_of::<TsPayload>());

  // `vec![0u8; _]` is only alignment 1, which `CMsgBuilder::new` refuses; back
  // the buffer with a `Vec<u64>` for ≥8-byte alignment as the tests above do.
  const TOTAL: usize = 128;
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; TOTAL / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `TOTAL` zeroed bytes; the slice fits inside the
  // allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), TOTAL) };
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push_bytes(SOL_SOCKET, TS_TYPE, &payload).expect("fits");
    b.finish()
  };

  // Every byte of the encoded cmsg must be genuinely INITIALIZED, not merely
  // zero — the distinction the padding defect turns on, and one that only a
  // real per-byte read can assert. A `to_vec`/`copy_from_slice` would propagate
  // uninitializedness instead of tripping over it, and the two assertions below
  // would not catch it either: `decode_unix_cmsgs` skips this cmsg and
  // `parse_rx_time` reads it back as a typed `timeval`, neither of which needs
  // the padding initialized. Under Miri this loop is the whole regression test;
  // in a normal build it is a cheap checksum.
  let mut acc: u64 = 0;
  for b in &buf[..written] {
    acc = acc.wrapping_add(u64::from(*b));
  }
  assert!(acc > 0, "the encoded cmsg must not be all-zero");

  // The decoder still walks the buffer, and still must not choke on a cmsg it
  // does not consume. Where the stamp would have gone there is no longer a
  // field, so the assertion below is about the mint instead.
  let mut meta = RecvMeta::empty(([0u8, 0, 0, 0], 0).into());
  decode_unix_cmsgs(&buf[..written], &mut meta, false);

  // One credit, sent a second before the stamp encoded above, and claimed on a
  // clock that has not stepped. A stamp recovered from the buffer is at-or-after
  // the send, so the claim weighs it and reports `Ordered`; a mint that recovered
  // nothing has no ordering evidence and can only report `Degraded`. The two
  // outcomes are what the stamp's presence is observable as.
  const ENCODED_SECS: u64 = 1_700_000_000;
  let body = b"a datagram this credit was recorded for";
  let sent = ClockPair::new(
    SystemTime::UNIX_EPOCH + Duration::from_secs(ENCODED_SECS - 1),
    StdInstant::now(),
  );
  let now = ClockPair::new(sent.wall, sent.mono);

  let mut tracker = SelfSendTracker::new();
  tracker.record(Family::V4, body, sent);
  tracker.seal_at(sent.mono);
  assert_eq!(
    tracker.claim_at(
      &RxDatagram::from_recv_parts(Family::V4, &body[..], &buf[..written]),
      now
    ),
    SelfSendMatch::Ordered,
    "hick-udp's parse, over the very bytes `Socket::recv` routes to the mint, is \
     what must recover the stamp — without it every claim runs degraded"
  );

  // The control, and it is what keeps the assertion above about the STAMP rather
  // than about the credit matching at all: the same credit, the same bytes, no
  // control buffer.
  tracker.record(Family::V4, body, sent);
  tracker.seal_at(sent.mono);
  assert_eq!(
    tracker.claim_at(&RxDatagram::without_stamp(Family::V4, &body[..]), now),
    SelfSendMatch::Degraded,
    "and a mint with no control buffer weighs no ordering evidence at all"
  );
}

// ============================================================================
// EVIDENCE FOR `has_ip_dstaddr_recvif`, the capability flip in this crate's
// `build.rs`.
//
// Item 4 (`MSG_CTRUNC` stays clear) is measured below on EVERY unix host: it is
// arithmetic over `libc`'s own `CMSG_SPACE` and needs no BSD to be true. Items
// 1-3 need a kernel that actually delivers the cmsgs, so they are the live
// tests after it — compiled only where the capability is set, and executed by
// ci.yml's `freebsd` job, which names them in `REQUIRED_COMPIO_EVIDENCE`.
//
// The synthesized-buffer test between them is not one of the four items. It
// pins the WIRING — that `decode_unix_cmsgs` routes the pair into the two
// witnesses at all — over bytes no kernel had to produce, so a break in the
// wiring fails on a host rather than only on the one target with a runner.
// ============================================================================

/// `CMSG_SPACE` for one cmsg of `payload` bytes, asked of `libc` rather than
/// derived: `CMSG_ALIGN` is 4 on x86 NetBSD and 8 on x86_64, and the header it
/// pads is 12 bytes on the BSDs against 16 on Linux, so no constant written here
/// would be right on more than one target.
#[cfg(all(unix, test))]
fn cmsg_space(payload: usize) -> usize {
  // SAFETY: `CMSG_SPACE` is pure length arithmetic on an integer and
  // dereferences nothing; `libc` marks it `unsafe` by convention only. This is
  // the same call `CMsgBuilder::push` makes in the production encode, which is
  // what makes this measurement and the buffer walk agree on every target.
  unsafe { libc::CMSG_SPACE(payload as libc::c_uint) as usize }
}

/// EVIDENCE ITEM 4 for `has_ip_dstaddr_recvif`: this driver's own control buffer
/// is large enough that the kernel never has to set `MSG_CTRUNC`.
///
/// This matters more than a sizing check normally would.
/// [`hick_udp::onlink::DestinationWitness::Lost`] REFUSES, and `MSG_CTRUNC` is
/// the only thing that mints it — so a buffer we sized too small is a
/// self-inflicted outage wearing the shape of a security decision. Adding the
/// `IP_RECVDSTADDR`/`IP_RECVIF` pair is exactly the kind of change that could
/// cause one, and the standing rule at the `build.rs` emit site requires the
/// figure to be MEASURED rather than asserted. [`AlignedCtrlBuf`] carried a
/// 256-byte capacity with no measurement behind it at all until this test.
///
/// The worst case is summed per-target from what [`enable_recv_cmsgs`] actually
/// enables, at the widest payload each cmsg can carry, with every term a literal
/// size taken from the kernel that emits it — not from a production function,
/// which would agree with itself whatever it did. One socket is one family, so
/// the two families are summed separately and the larger taken.
///
/// It is the same set `hick_udp::try_bind_v4` enables on the very same fd (see
/// `endpoint.rs`), so the union of the two enables is this sum and not more.
#[cfg(all(unix, test))]
#[test]
fn control_buffer_holds_every_cmsg_this_target_enables() {
  // The IPv4 destination/interface shape. Exactly one of the two is enabled on
  // any target — see `build.rs` — so this is a choice, not a sum.
  let v4_destination = if cfg!(has_ip_pktinfo) {
    // `struct in_pktinfo`, 12 bytes on Linux/Apple: ipi_ifindex, ipi_spec_dst,
    // ipi_addr.
    cmsg_space(12)
  } else if cfg!(has_ip_dstaddr_recvif) {
    // Two separate cmsgs. `IP_RECVDSTADDR` is a bare `struct in_addr`.
    // `IP_RECVIF` is a `struct sockaddr_dl` of `sdl_len` bytes, and the kernels
    // copy the interface's own — so the widest payload is the full struct: 54
    // bytes on FreeBSD (46-byte `sdl_data`), 32 on OpenBSD, 24 on DragonFly and
    // 20 on NetBSD. FreeBSD's is the largest and is used for all four, so the
    // bound holds on every one of them whatever this host happens to be.
    cmsg_space(4) + cmsg_space(54)
  } else {
    0
  };
  // `IP_RECVTTL`: an `int` on Linux, a single `u_char` on the BSDs. The wider
  // reading is the safe one here.
  let v4_ttl = if cfg!(has_recv_hoplimit) {
    cmsg_space(4)
  } else {
    0
  };
  // `struct in6_pktinfo` is 20 bytes (ipi6_addr + ipi6_ifindex); `IPV6_HOPLIMIT`
  // is an `int`.
  let v6_destination = if cfg!(has_ipv6_pktinfo) {
    cmsg_space(20)
  } else {
    0
  };
  let v6_hoplimit = if cfg!(has_recv_hoplimit) {
    cmsg_space(4)
  } else {
    0
  };
  // Shared by both families: a `timespec` on Linux/Android, a `timeval`
  // elsewhere — 16 bytes either way.
  let timestamp = if cfg!(has_recv_timestamp) {
    cmsg_space(16)
  } else {
    0
  };

  let v4_worst = v4_destination + v4_ttl + timestamp;
  let v6_worst = v6_destination + v6_hoplimit + timestamp;
  let worst = v4_worst.max(v6_worst);

  // The buffer itself, read off the production constant rather than restated.
  let capacity = CMSG_CAP;
  eprintln!("cmsg worst case: IPv4 {v4_worst}, IPv6 {v6_worst}, CMSG_CAP {capacity}");
  assert!(
    worst <= capacity,
    "control buffer too small: this target's worst case is {worst} bytes (IPv4 \
     {v4_worst}, IPv6 {v6_worst}) against a {capacity}-byte AlignedCtrlBuf. \
     MSG_CTRUNC mints DestinationWitness::Lost, which REFUSES, so this would be \
     a self-inflicted outage and not a degradation — grow CMSG_CAP and update \
     its doc"
  );
  // Headroom for a cmsg this crate did not ask for. Not a second spelling of the
  // check above: this one fails while the buffer still technically fits, which
  // is the point at which the figure in `AlignedCtrlBuf`'s own doc has stopped
  // holding. 256 passed the first assertion and failed this one on FreeBSD,
  // which is why the buffer is 512.
  assert!(
    worst * 2 <= capacity,
    "this target's worst case is {worst} bytes against a {capacity}-byte \
     AlignedCtrlBuf — under 2x headroom for an unrequested cmsg. Re-derive the \
     figure in AlignedCtrlBuf's doc before relaxing this"
  );
  // The completion marker CI requires for evidence item 4. Spelled out rather
  // than routed through `evidence_complete`, which only exists where the BSD
  // capability is set; this test runs on every unix target.
  // Leading newline for the same reason as `evidence_complete`'s.
  eprintln!("\nhick-compio-evidence-complete: control_buffer_holds_every_cmsg_this_target_enables");
}

/// Emit the completion marker for one evidence test.
///
/// **Called only as the last statement, after every assertion.** CI requires
/// this line rather than libtest's `test <name> ... ok`, because those are
/// different claims: the status line says the test function RETURNED, and a
/// function that returned early because a precondition was unmet returns `ok`
/// just as loudly as one that asserted. This line says the test reached its
/// end, which is the only thing that makes the four evidence items behind
/// `has_ip_dstaddr_recvif` rest on execution rather than on a process starting.
///
/// It is not a defence against a hostile branch — that branch could print this
/// line directly, exactly as it could hollow out the assertions above it. It
/// closes the accidental case: an unmet precondition, a silently skipped body,
/// a test renamed out of the required list. See `ci.yml`'s `freebsd` job.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
fn evidence_complete(test: &str) {
  // The LEADING NEWLINE is load-bearing. Under `--nocapture` libtest writes
  // `test <name> ... ` to stdout without a newline, runs the test, then writes
  // `ok`; a marker printed into that gap lands mid-line and no whole-line match
  // finds it. The newline closes libtest's partial line so the marker always
  // starts at column 0, which is what lets the check stay an exact whole-line
  // match — a substring match would find `...-complete: foo` inside
  // `...-complete: foo_v2` and re-open the rename hole the whole-line matches
  // exist to close.
  eprintln!("\nhick-compio-evidence-complete: {test}");
}

/// Read one integer socket option back, so an enable can be checked against what
/// the kernel actually holds rather than against its own return code.
///
/// The GET direction of `IP_RECVDSTADDR`/`IP_RECVIF` is handled by all four BSD
/// kernels — cited per kernel at `hick-udp/build.rs`'s evidence item 1 — which is
/// what makes it safe to treat a zero read-back as a failure.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
fn get_int(
  fd: std::os::fd::RawFd,
  level: libc::c_int,
  optname: libc::c_int,
) -> std::io::Result<libc::c_int> {
  let mut val: libc::c_int = 0;
  let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
  // SAFETY: `&mut val` is a valid, writable pointer to a `c_int` and `len` is
  // its size; `getsockopt` writes at most `len` bytes there and updates `len`.
  let rc = unsafe {
    libc::getsockopt(
      fd,
      level,
      optname,
      &mut val as *mut _ as *mut _,
      &mut len as *mut _,
    )
  };
  if rc != 0 {
    Err(std::io::Error::last_os_error())
  } else {
    Ok(val)
  }
}

/// EVIDENCE ITEM 1 for `has_ip_dstaddr_recvif`, verbatim: the enable returns 0
/// on the AF_INET socket this driver wraps, and the kernel holds both flags
/// afterwards.
///
/// [`enable_recv_cmsgs`] is the whole subject — the function `Socket::from_std`
/// calls, driven here directly so no runtime is needed and no delivery race can
/// reach it. It applies both options with a fatal `?`, so a `setsockopt` failure
/// would already be an `Err` here; the read-back below is not a second copy of
/// that check but the observable half of it, which is what catches a kernel that
/// accepted the call without holding the flag.
///
/// Every precondition is FATAL. A run where the bind never happened has proven
/// nothing about the enable and must not report `ok`.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
#[test]
fn bsd_ipv4_enable_recv_cmsgs_sets_the_receive_metadata_pair() {
  use std::os::fd::AsRawFd;

  let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).expect(
    "binding a wildcard AF_INET socket must succeed: this IS evidence item 1, so a bind that \
     did not happen is a failure and never a skip",
  );
  enable_recv_cmsgs(&sock).expect(
    "enable_recv_cmsgs must apply IP_RECVDSTADDR + IP_RECVIF on an AF_INET socket — the whole \
     has_ip_dstaddr_recvif capability rests on this enable taking",
  );
  let fd = sock.as_raw_fd();
  let dstaddr = get_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR)
    .expect("getsockopt for IP_RECVDSTADDR must succeed on this target");
  let recvif = get_int(fd, libc::IPPROTO_IP, libc::IP_RECVIF)
    .expect("getsockopt for IP_RECVIF must succeed on this target");
  assert_ne!(
    dstaddr, 0,
    "IP_RECVDSTADDR must read back as enabled after enable_recv_cmsgs"
  );
  assert_ne!(
    recvif, 0,
    "IP_RECVIF must read back as enabled after enable_recv_cmsgs"
  );
  evidence_complete("bsd_ipv4_enable_recv_cmsgs_sets_the_receive_metadata_pair");
}

/// The `IP_RECVIF` payload as a byte image: a `struct sockaddr_dl` cut to its
/// FIXED PREFIX, which is the shortest payload the BSD kernels emit (their "no
/// receive interface" dummy is exactly this long) and the only part
/// `hick-udp`'s decoder may read — the four targets disagree on the struct's
/// total size.
///
/// `sdl_index` is a HOST-order `u_short` at offset 2. Built by hand rather than
/// through `libc::sockaddr_dl` so this test states the layout it expects instead
/// of borrowing it from the same source the parser's `const _` assertions pin
/// against.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
fn sockaddr_dl_prefix_bytes(index: u16) -> Vec<u8> {
  let mut b = vec![0u8; 8];
  b[0] = 8; // sdl_len
  b[1] = libc::AF_LINK as u8; // sdl_family
  b[2..4].copy_from_slice(&index.to_ne_bytes()); // sdl_index, host order
  b
}

/// The wiring behind evidence items 2 and 3, over bytes no kernel had to
/// produce: `decode_unix_cmsgs` must route an `IP_RECVDSTADDR` + `IP_RECVIF`
/// pair into BOTH witnesses on the [`RecvMeta`] it was handed.
///
/// Not one of the four evidence items — it proves nothing about what a kernel
/// delivers — and that is exactly its value. Items 2 and 3 run only where a real
/// BSD does, and this runs wherever the capability compiles, so a wiring break
/// (a dropped `meta.destination =`, a call deleted from `decode_unix_cmsgs`) is
/// caught by the same `cargo test` that compiles it rather than only by the one
/// target with a runner. It is silent and has no preconditions, so libtest's
/// status line and "concluded" are the same claim.
///
/// The `IP_RECVDSTADDR` payload is the GROUP, so this also pins that the group
/// address survives the decode as itself: reading the receiving interface's own
/// address instead — the `ipi_spec_dst` mistake the `IP_PKTINFO` arm carries a
/// comment about — would make every multicast arrival look unicast.
///
/// Covers the COMPLETE pair and the nothing-recovered case. A partial pair is
/// its own subject, because what the absent half must say depends on
/// `MSG_CTRUNC` rather than on the bytes:
/// [`bsd_ipv4_decode_spells_each_absent_half_by_whose_failure_it_was`].
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
#[test]
fn bsd_ipv4_decode_recovers_both_witnesses_from_a_synthesized_pair() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};
  use hick_udp::onlink::{DestinationWitness, IfaceWitness};

  const TOTAL: usize = 256;
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; TOTAL / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `TOTAL` zeroed bytes; the slice fits inside the
  // allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), TOTAL) };
  // Network-order `struct in_addr` for 224.0.0.251, i.e. the four octets
  // verbatim — which is exactly what the kernels copy out of `ip->ip_dst`.
  let group = [224u8, 0, 0, 251];
  let iface_index: u16 = 9;
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push_bytes(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, &group)
      .expect("the dstaddr cmsg fits");
    b.push_bytes(
      libc::IPPROTO_IP,
      libc::IP_RECVIF,
      &sockaddr_dl_prefix_bytes(iface_index),
    )
    .expect("the recvif cmsg fits");
    b.finish()
  };

  let peer: SocketAddr = ([192, 0, 2, 1], 5353).into();
  let mut meta = RecvMeta::empty(peer);
  // Production order: the absence is declared first, so what follows is an
  // overwrite and not a fill-in. `false` = no MSG_CTRUNC.
  meta.declare_cmsg_absent(false);
  decode_unix_cmsgs(&buf[..written], &mut meta, false);

  assert_eq!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "the IP_RECVDSTADDR payload is the IP header destination and must reach the \
     destination witness as itself — §11 selects its local-link test on this value"
  );
  assert_eq!(
    meta.iface_witness(),
    IfaceWitness::Witnessed(
      core::num::NonZeroU32::new(u32::from(iface_index)).expect("a non-zero test index")
    ),
    "the IP_RECVIF sdl_index must reach the interface witness"
  );

  // The nothing-recovered case is the one `decode_bsd_ipv4_dstaddr_recvif`
  // leaves alone, so the CTRUNC-aware absence the caller declared has to survive
  // it. `Lost` and not `Declined` is what makes that distinction observable.
  //
  // The buffer is NON-EMPTY and carries a SHORT `IP_RECVDSTADDR` — two payload
  // bytes where an `in_addr` is four. An empty buffer would prove nothing here:
  // `decode_unix_cmsgs` returns at its own `ctrl.is_empty()` guard before
  // reaching the parser at all, so the assertion would hold whatever the parser
  // arm did. That is not hypothetical — it is how the first version of this
  // assertion passed a mutation that clobbered the destination before parsing.
  // A short cmsg reaches the parser, is refused by it, and so pins the early
  // return on `Err` as well as that a truncated cmsg is skipped rather than read
  // as garbage.
  let short_written = {
    let mut b = CMsgBuilder::new(buf);
    b.push_bytes(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, &[0u8, 0])
      .expect("the short dstaddr cmsg fits");
    b.finish()
  };
  let mut absent_meta = RecvMeta::empty(peer);
  absent_meta.declare_cmsg_absent(true);
  decode_unix_cmsgs(&buf[..short_written], &mut absent_meta, true);
  assert_eq!(
    absent_meta.destination_witness(),
    DestinationWitness::Lost,
    "with nothing recovered the parser reports Err and the declared MSG_CTRUNC \
     absence must stand — a parser over a byte slice cannot see the message \
     header, so it can never mint Lost itself"
  );
  assert_eq!(
    absent_meta.iface_witness(),
    IfaceWitness::Lost,
    "and the interface half of that same declared absence"
  );
}

/// A PARTIAL pair — one cmsg of the two — must spell the absent half by WHOSE
/// failure it was, and that is decided by `MSG_CTRUNC` and not by the parser.
///
/// # The defect this exists to pin
///
/// `parse_dstaddr_recvif_v4` is defined over a byte slice. It cannot see
/// `msg_flags`, so it spells every absence `Declined` —
/// `from_reporting_path(.., false)`, hardcoded — because
/// [`hick_udp::onlink::DestinationWitness::Lost`] accuses OUR control buffer and
/// a parser cannot know whether that buffer overflowed. An adapter that copied
/// BOTH of the parser's witnesses onto the meta therefore overwrote a correct
/// `Lost` with a wrong `Declined` whenever one cmsg of the pair survived a
/// truncation the other did not — turning REFUSE into DEGRADE on the two squares
/// this capability exists to close. The first version of this decode did exactly
/// that, and an earlier version of this test asserted `Declined` under
/// truncation and so locked it in.
///
/// # Why the rows are what they are
///
/// The two cmsgs are separately allocated by `sbcreatecontrol`, so either can
/// arrive without the other, and the reason differs per row:
///
/// # Each half is promoted ALONE, and the privilege rule is not here
///
/// A version of this decode promoted the destination only when the interface
/// half arrived beside it, to keep §11 arm one's "regardless of source IP
/// address" exemption from a datagram nothing scoped to the bound link. The rule
/// was right; enforcing it by dropping the address was not. The address is what
/// every NEGATIVE class is decided by, so dropping it stopped a foreign group
/// being refused AS a foreign group and reopened the broadcast class beside it.
///
/// The rule now lives in `hick_onlink::admits_ingress`, over the witness PAIR
/// both halves reach anyway: an unscoped datagram loses arm one and takes §11's
/// source arm, and keeps every refusal the destination earns. That also covers
/// the `IP_PKTINFO` square, which is one cmsg and can carry the same pair — a
/// rule written at this decoder never could.
///
/// So both halves are promoted alone here, and the rows below say what the
/// PARSER recovered, which is now also what the meta carries.
///
/// * NOT truncated, `IP_RECVDSTADDR` only — NetBSD's documented psref square.
///   `ip_savecontrol` emits `IP_RECVDSTADDR` before its
///   `m_get_rcvif_psref() == NULL -> return` and `IP_RECVIF` after it, so a
///   detached receive interface loses the interface cmsg and nothing else. The
///   kernel answered and named no interface: `Declined`, which DEGRADES. Our
///   buffer lost nothing, so `Lost` here would refuse a datagram nobody failed
///   to deliver.
/// * NOT truncated, `IP_RECVIF` only — the mirror, under mbuf pressure: every
///   BSD builds ancillary mbufs with `M_NOWAIT` and skips one it cannot allocate
///   with no error and no flag. `Declined` again, and degrading is the whole
///   point — refusing would take the responder off the air during the flood that
///   caused the shortage.
/// * TRUNCATED, either half absent — OUR buffer was too small. `Lost`, which
///   REFUSES. Nothing about the kernel's behaviour changed; what changed is that
///   the failure is ours, and §11 is entitled to refuse on our own bug where it
///   must not refuse on the kernel's shortage.
///
/// The half that DID arrive is `Witnessed` in every row, truncation included. A
/// partially-copied cmsg cannot present as `Witnessed` — `CmsgIter` ends the
/// walk on a `cmsg_len` that overruns the slice and the payload decoders require
/// their full fixed length — so keeping it is not optimism, and discarding it
/// would refuse a datagram on a witness the kernel really did deliver.
///
/// Expectations are enumerated literally, never computed from
/// `control_truncated` by the same rule the code under test applies.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
#[test]
fn bsd_ipv4_decode_spells_each_absent_half_by_whose_failure_it_was() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};
  use hick_udp::onlink::{DestinationWitness, IfaceWitness};

  const TOTAL: usize = 256;
  let peer: SocketAddr = ([192, 0, 2, 1], 5353).into();
  let group = [224u8, 0, 0, 251];
  let iface_index: u16 = 9;
  let witnessed_dst = DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)));
  let witnessed_if = IfaceWitness::Witnessed(
    core::num::NonZeroU32::new(u32::from(iface_index)).expect("a non-zero test index"),
  );

  // (truncated, push dstaddr, push recvif, expected destination, expected iface,
  //  what the row is about)
  let rows: [(bool, bool, bool, DestinationWitness, IfaceWitness, &str); 6] = [
    // The COMPLETE pair, both truncation states. Here and only here does the
    // destination reach the group arm, because here and only here is there a
    // link proof beside it for `arrived_on_bound_interface` to check.
    (
      false,
      true,
      true,
      witnessed_dst,
      witnessed_if,
      "no truncation, both cmsgs: the pair is complete, so the destination is \
       promoted and the interface is there to scope arm one with",
    ),
    (
      true,
      true,
      true,
      witnessed_dst,
      witnessed_if,
      "TRUNCATED but both cmsgs arrived whole: a partially copied cmsg is short \
       and cannot present as Witnessed, so MSG_CTRUNC costs this datagram \
       nothing",
    ),
    (
      false,
      true,
      false,
      // The kernel gave us this address and the meta carries it. It buys LESS
      // than a paired one — `admits_ingress` withholds §11 arm one's source
      // exemption from a datagram nothing scoped to the bound link — but it is
      // still what every negative class is decided by, and an earlier version of
      // this decode dropped it here and lost those refusals with it. What a
      // witness buys is the gate's question; what arrived is this function's.
      witnessed_dst,
      IfaceWitness::Declined,
      "no truncation, destination only: the address the kernel produced is \
       carried, and the gate decides what it is worth without it",
    ),
    (
      false,
      false,
      true,
      DestinationWitness::Declined,
      witnessed_if,
      "no truncation, interface only: the kernel emitted no destination, so the \
       destination half DEGRADES to the source-prefix arm",
    ),
    (
      true,
      true,
      false,
      // The destination is promoted under truncation too: a partially copied
      // cmsg is short and cannot present as `Witnessed`, so this address really
      // did arrive whole. The MISSING half is `Lost` rather than `Declined`
      // because our own buffer is what lost it, and `arrived_on_bound_interface`
      // REFUSES on `Lost` — so this row refuses on the interface half, and the
      // destination it refuses with is honest about having been there.
      witnessed_dst,
      IfaceWitness::Lost,
      "TRUNCATED, destination only: the missing interface is OUR buffer's \
       failure and REFUSES, and the destination that did arrive is still \
       carried",
    ),
    (
      true,
      false,
      true,
      DestinationWitness::Lost,
      witnessed_if,
      "TRUNCATED, interface only: the missing destination is OUR buffer's \
       failure and must REFUSE — a Declined here reopens the in-prefix \
       broadcast admission this capability exists to close",
    ),
  ];

  for (truncated, push_dst, push_if, want_dst, want_if, what) in rows {
    assert!(
      core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>(),
      "{what}: the u64 backing must satisfy cmsghdr alignment"
    );
    let mut backing: Vec<u64> = vec![0u64; TOTAL / core::mem::size_of::<u64>()];
    // SAFETY: backing owns `TOTAL` zeroed bytes; the slice fits inside the
    // allocation and stays borrowed for this iteration.
    let buf: &mut [u8] =
      unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), TOTAL) };
    let written = {
      let mut b = CMsgBuilder::new(buf);
      if push_dst {
        b.push_bytes(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, &group)
          .expect("the dstaddr cmsg fits");
      }
      if push_if {
        b.push_bytes(
          libc::IPPROTO_IP,
          libc::IP_RECVIF,
          &sockaddr_dl_prefix_bytes(iface_index),
        )
        .expect("the recvif cmsg fits");
      }
      b.finish()
    };
    // Production order: declare the absence first — that is the only step that
    // sees MSG_CTRUNC — then decode over the bytes.
    let mut meta = RecvMeta::empty(peer);
    meta.declare_cmsg_absent(truncated);
    decode_unix_cmsgs(&buf[..written], &mut meta, truncated);
    assert_eq!(meta.destination_witness(), want_dst, "{what}");
    assert_eq!(meta.iface_witness(), want_if, "{what}");

    // The witnesses are the means; THIS is the end. Drive the real §11 boundary
    // with what the decoder produced, for an OFF-PREFIX source sending to the
    // group under FreeBSD/DragonFly conditions (`delivery: None` — those two
    // bind no `MSG_MCAST`), and require that a datagram is admitted only where
    // something actually proved it reached us on the bound link.
    //
    // Asserting the witnesses alone would not have caught the defect this test
    // was rewritten for: `Witnessed(group)` + `Declined` looks perfectly
    // reasonable as a pair of values, and it once WAS an unconditional admit
    // with no link proof. What decides it is `admits_ingress`, which withholds
    // §11 arm one's source exemption from a datagram nothing scoped — so this
    // assertion is about the pair this decoder hands over, not about a rule this
    // crate implements. It must keep passing whether the rule lives here or
    // there, and it now lives there.
    let local_addrs = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24u8)];
    let bound = hick_udp::onlink::BoundLink::new(u32::from(iface_index), false, &local_addrs);
    let off_prefix: SocketAddr = ([203, 0, 113, 9], 5353).into();
    let verdict = hick_udp::onlink::admits_ingress(
      off_prefix,
      meta.destination_witness(),
      None,
      bound,
      meta.iface_witness(),
    );
    // Literal per row, never computed: admitted exactly when the pair was
    // complete, which is exactly when the link was proven.
    let want_admit = push_dst && push_if;
    assert_eq!(
      verdict.is_admit(),
      want_admit,
      "{what}: an off-prefix group datagram may be admitted only with the link \
       proof arm one's exemption rests on"
    );
  }
}

/// The index of an UP loopback interface.
///
/// FATAL rather than `Option`: both live evidence tests need loopback to carry
/// the datagram, and a host without one cannot produce this evidence — which is
/// a finding, not a reason to report success.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
fn up_loopback_index() -> u32 {
  let ifaces = getifs::interfaces().expect(
    "interface enumeration must succeed: the BSD IPv4 evidence tests cannot run without it, \
     and returning early here would report success for a run that proved nothing",
  );
  ifaces
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP))
    .map(|i| i.index())
    .expect("no UP loopback interface: the BSD IPv4 evidence tests cannot be exercised here")
}

/// Read from `sock` until the datagram carrying exactly `want` arrives.
///
/// Matching on the payload is what keeps these tests honest on a host with real
/// mDNS traffic: an assertion about "the destination of the datagram that came
/// back" is worth nothing if the datagram came from somebody else's responder.
/// FATAL on timeout — a receive that never happened proves nothing.
///
/// ONE timeout around the whole loop rather than one per receive. A per-receive
/// timeout drops an in-flight `recv_msg` on every tick, and a datagram that
/// lands in the window between readiness and cancellation is consumed by a
/// future nobody is awaiting any more — which would turn this into a flaky test
/// that reports "never arrived" for a datagram the kernel did deliver. Wrapping
/// the loop means the only cancellation happens after the deadline, when the
/// test has already failed.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
async fn recv_matching(sock: &super::Socket, want: &[u8]) -> RecvMeta {
  compio::time::timeout(std::time::Duration::from_secs(10), async {
    loop {
      let (data, meta) = sock
        .recv(2048)
        .await
        .expect("the receive path itself must not fail while waiting");
      if data == want {
        return meta;
      }
    }
  })
  .await
  .expect("the probe datagram never arrived: this evidence item cannot be established here")
}

/// EVIDENCE ITEM 2 for `has_ip_dstaddr_recvif`: a datagram to 224.0.0.251 is
/// witnessed as arriving at 224.0.0.251, on the interface that carried it.
///
/// End to end through THIS driver's receive path — compio's `recv_msg` and
/// [`decode_unix_cmsgs`], never `hick_udp::recv_with_meta` — which is the half
/// of the kernel fact that belongs to this crate. That `ip_savecontrol` copies
/// `ip->ip_dst` verbatim is established once, per kernel, at
/// `hick-udp/build.rs`'s item 2.
///
/// The exact group address is asserted, not "is multicast": RFC 6762 §11's group
/// arm is stated over the mDNS group and an over-approximation would admit any
/// multicast destination on its strength.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
#[compio::test]
async fn bsd_ipv4_recv_witnesses_the_group_destination() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};
  use hick_udp::{MulticastOptionsV4, onlink::DestinationWitness, try_bind_v4, try_join_v4};

  let lo = up_loopback_index();
  // Sender and receiver both go through `try_bind_v4`, which pins IP_MULTICAST_IF
  // to `lo` so the datagram leaves on loopback. Only the receiver joins. Both are
  // on 5353 with SO_REUSEPORT, which is safe for a MULTICAST probe — every joined
  // member of the reuse group is delivered a copy — and would not be for the
  // unicast one below.
  let tx = try_bind_v4(MulticastOptionsV4::new(lo))
    .expect("try_bind_v4 for the sender must succeed: this IS evidence item 2");
  let rx = try_bind_v4(MulticastOptionsV4::new(lo))
    .expect("try_bind_v4 for the receiver must succeed: this IS evidence item 2");
  try_join_v4(&rx, lo).expect("joining 224.0.0.251 on loopback is part of evidence item 2");
  let tx = super::Socket::from_std(tx)
    .await
    .expect("wrapping the sender must succeed");
  let rx = super::Socket::from_std(rx)
    .await
    .expect("wrapping the receiver must succeed");

  let payload = b"hick-compio bsd group destination probe";
  let dst: SocketAddr = (Ipv4Addr::new(224, 0, 0, 251), 5353).into();
  tx.send_to(payload, dst, None)
    .await
    .expect("sending to the group must succeed: evidence item 2 needs the datagram");

  let meta = recv_matching(&rx, payload).await;
  assert_eq!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "a datagram to the mDNS group must be witnessed AT the group, exactly — \
     anything else sends it to §11's source-prefix arm, which refuses an on-link \
     peer sourcing from a prefix this interface does not carry"
  );
  assert_eq!(
    meta.interface_index(),
    lo,
    "and on the interface that actually carried it — telling 'arrived elsewhere' \
     apart from 'the platform never says' is the whole value of this capability"
  );
  evidence_complete("bsd_ipv4_recv_witnesses_the_group_destination");
}

/// EVIDENCE ITEM 3 for `has_ip_dstaddr_recvif`: a datagram to one of the host's
/// own addresses is witnessed at THAT address, so §11's group arm is not taken
/// for a unicast arrival.
///
/// Also evidence item 1 end to end. The receiving socket is a plain
/// `UdpSocket::bind` wrapped by `Socket::from_std`, so the ONLY thing that
/// enabled the pair on it is this crate's own [`enable_recv_cmsgs`] —
/// `hick_udp::try_bind_v4` never touches this fd. A decode that worked only
/// because some other crate's bind had set the options would fail here.
///
/// Ephemeral port, deliberately: `try_bind_v4` binds 5353 with SO_REUSEPORT, and
/// a UNICAST datagram to a reuse group is delivered to exactly one member of it,
/// which on any host running another responder is not necessarily us.
#[cfg(all(unix, has_ip_dstaddr_recvif, test))]
#[compio::test]
async fn bsd_ipv4_recv_witnesses_a_unicast_destination() {
  use core::net::{IpAddr, Ipv4Addr};
  use hick_udp::onlink::DestinationWitness;

  let rx_std = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
    .expect("binding 127.0.0.1:0 must succeed: this IS evidence item 3");
  let local = rx_std
    .local_addr()
    .expect("the receiver's own address is what this item asserts against");
  let rx = super::Socket::from_std(rx_std)
    .await
    .expect("wrapping the receiver must succeed — from_std is what enables the pair here");

  let tx = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
    .expect("binding the sender must succeed: this IS evidence item 3");
  let payload = b"hick-compio bsd unicast destination probe";
  tx.send_to(payload, local)
    .expect("sending the unicast probe must succeed");

  let meta = recv_matching(&rx, payload).await;
  assert_eq!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(local.ip()),
    "a unicast datagram must be witnessed at the address it was sent to"
  );
  assert_ne!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "and must NOT collapse onto the group, which is the reading that would admit \
     a unicast arrival through §11's group arm"
  );
  evidence_complete("bsd_ipv4_recv_witnesses_a_unicast_destination");
}
