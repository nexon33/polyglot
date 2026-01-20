use std::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
pub struct TensorHeader {
    // SAFETY FIELDS (must be first)
    pub ref_count: AtomicU32,    // ARC-style reference counting
    pub borrow_state: AtomicU32, // 0 = free, 1+ = shared borrows, u32::MAX = exclusive

    // DATA FIELDS
    pub data_ptr: u32,
    pub data_len: u32,
    pub shape_ptr: u32,
    pub ndim: u32,
    pub dtype: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowError {
    AlreadyMutablyBorrowed,
    AlreadyImmutablyBorrowed,
    TooManyBorrows,
}

impl TensorHeader {
    pub const EXCLUSIVE_BORROW: u32 = u32::MAX;

    /// Increment reference count (called when crossing boundary)
    pub fn retain(&self) {
        let old = self.ref_count.fetch_add(1, Ordering::SeqCst);
        if old == u32::MAX {
            panic!("Reference count overflow");
        }
    }

    /// Decrement reference count, returns true if should deallocate
    pub fn release(&self) -> bool {
        let old = self.ref_count.fetch_sub(1, Ordering::SeqCst);
        if old == 0 {
            panic!("Double free detected");
        }
        old == 1 // Was 1, now 0 → deallocate
    }

    /// Try to acquire shared (immutable) borrow
    pub fn try_borrow(&self) -> Result<(), BorrowError> {
        loop {
            let state = self.borrow_state.load(Ordering::SeqCst);

            if state == Self::EXCLUSIVE_BORROW {
                return Err(BorrowError::AlreadyMutablyBorrowed);
            }

            let new_state = state.checked_add(1).ok_or(BorrowError::TooManyBorrows)?;

            if self
                .borrow_state
                .compare_exchange(state, new_state, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(());
            }
            // CAS failed, retry
        }
    }

    /// Release shared borrow
    pub fn unborrow(&self) {
        let old = self.borrow_state.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(old > 0 && old != Self::EXCLUSIVE_BORROW);
    }

    /// Try to acquire exclusive (mutable) borrow
    pub fn try_borrow_mut(&self) -> Result<(), BorrowError> {
        match self.borrow_state.compare_exchange(
            0,
            Self::EXCLUSIVE_BORROW,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => Ok(()),
            Err(state) => {
                if state == Self::EXCLUSIVE_BORROW {
                    Err(BorrowError::AlreadyMutablyBorrowed)
                } else {
                    Err(BorrowError::AlreadyImmutablyBorrowed)
                }
            }
        }
    }

    /// Release exclusive borrow
    pub fn unborrow_mut(&self) {
        let old = self.borrow_state.swap(0, Ordering::SeqCst);
        debug_assert!(old == Self::EXCLUSIVE_BORROW);
    }
}
