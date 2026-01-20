use crate::header::{BorrowError, TensorHeader};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

// Placeholder for now, can be expanded to constrain T
pub trait TensorElement {}

// Implement for common types
impl TensorElement for f64 {}
impl TensorElement for f32 {}
impl TensorElement for i64 {}
impl TensorElement for i32 {}
impl TensorElement for u64 {}
impl TensorElement for u32 {}
impl TensorElement for u8 {}

pub struct Tensor<T> {
    header: *mut TensorHeader,
    _marker: PhantomData<T>,
}

// Emulate external WASM alloc/free for now if needed,
// or assume we are inside WASM so standard allocator works?
// The spec mentions "wasm_free(header.data_ptr)".
// In a real WASM env, `alloc` and `free` are usually exported or provided by allocator.
// For this library implementation, we'll assume we are compiling TO Wasm,
// so we can use Rust's `Box` or `Vec` to manage memory initially, or raw alloc layouts.

// However, the spec says "Python creates Tensor... passes pointer to Rust".
// This means the memory is already allocated.
// When `release()` returns true, we must deallocate.
// Deallocating memory allocated by Python (or another guest language) requires
// agreement on the allocator.
// Standard practice: The host provides `alloc` and `dealloc` imports, OR
// every language links `dlmalloc`/`talc` and exports `malloc`/`free`.

// For this implementation, we will use a placeholder `wasm_free` function
// that would bind to the actual deallocation logic.

unsafe fn wasm_free(ptr: u32) {
    // Logic to free memory at ptr
    // This requires knowing the layout/size or having a malloc-compatible free.
    // In a shared-nothing-but-linear-memory setup, all plugins usually share the SAME allocator instance (e.g. linked in)
    // or call each other's free.

    // For specific implementation, we will stub this.
    // In production, this calls a linked `free(void* ptr)`.
    if ptr != 0 {
        // extern "C" { fn free(ptr: *mut u8); }
        // free(ptr as *mut u8);
    }
}

impl<T: TensorElement> Tensor<T> {
    /// Wrap a raw header pointer, incrementing ref count
    pub unsafe fn from_raw(header: *mut TensorHeader) -> Self {
        (*header).retain();
        Tensor {
            header,
            _marker: PhantomData,
        }
    }

    /// Create a new tensor with zeros
    pub fn zeros(shape: &[usize]) -> Self
    where
        T: Default + Clone,
    {
        let total_len: usize = shape.iter().product();

        // Allocate data
        let mut data = Vec::with_capacity(total_len);
        data.resize(total_len, T::default());
        let data_ptr = data.as_mut_ptr() as u32;
        std::mem::forget(data); // Hand off to TensorHeader management

        // Allocate shape
        let mut shape_vec: Vec<u32> = shape.iter().map(|&x| x as u32).collect();
        let shape_ptr = shape_vec.as_mut_ptr() as u32;
        std::mem::forget(shape_vec);

        // Allocate header starting with ref_count 1
        let header = Box::new(TensorHeader {
            ref_count: std::sync::atomic::AtomicU32::new(1),
            borrow_state: std::sync::atomic::AtomicU32::new(0),
            data_ptr,
            data_len: total_len as u32,
            shape_ptr,
            ndim: shape.len() as u32,
            dtype: 0,
            flags: 0,
        });

        Tensor {
            header: Box::into_raw(header),
            _marker: PhantomData,
        }
    }

    /// Borrow the data immutably (returns a guard)
    pub fn borrow(&self) -> Result<TensorRef<'_, T>, BorrowError> {
        unsafe {
            (*self.header).try_borrow()?;
            Ok(TensorRef { tensor: self })
        }
    }

    /// Borrow the data mutably (returns a guard)
    pub fn borrow_mut(&mut self) -> Result<TensorRefMut<'_, T>, BorrowError> {
        unsafe {
            (*self.header).try_borrow_mut()?;
            Ok(TensorRefMut { tensor: self })
        }
    }

    pub fn shape(&self) -> Vec<usize> {
        unsafe {
            let header = &*self.header;
            let shape_ptr = header.shape_ptr as *const u32;
            (0..header.ndim as usize)
                .map(|i| *shape_ptr.add(i) as usize)
                .collect()
        }
    }
}

impl<T> Drop for Tensor<T> {
    fn drop(&mut self) {
        unsafe {
            if (*self.header).release() {
                // ref_count hit 0, deallocate
                let header = &*self.header;
                wasm_free(header.data_ptr);
                wasm_free(header.shape_ptr);
                wasm_free(self.header as u32);
            }
        }
    }
}

impl<T: std::fmt::Debug + TensorElement> std::fmt::Debug for Tensor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shape = self.shape();
        write!(f, "Tensor(shape={:?}, type={})", shape, std::any::type_name::<T>())
    }
}

impl<T> Clone for Tensor<T> {
    fn clone(&self) -> Self {
        unsafe {
            (*self.header).retain();
        }
        Tensor {
            header: self.header,
            _marker: PhantomData,
        }
    }
}

/// RAII guard for immutable borrow
pub struct TensorRef<'a, T> {
    tensor: &'a Tensor<T>,
}

impl<'a, T: TensorElement> TensorRef<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            let header = &*self.tensor.header;
            let ptr = header.data_ptr as *const T;
            std::slice::from_raw_parts(ptr, header.data_len as usize)
        }
    }
}

impl<'a, T> Drop for TensorRef<'a, T> {
    fn drop(&mut self) {
        unsafe {
            (*self.tensor.header).unborrow();
        }
    }
}

/// RAII guard for mutable borrow
pub struct TensorRefMut<'a, T> {
    tensor: &'a mut Tensor<T>,
}

impl<'a, T: TensorElement> TensorRefMut<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            let header = &*self.tensor.header;
            let ptr = header.data_ptr as *const T;
            std::slice::from_raw_parts(ptr, header.data_len as usize)
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe {
            let header = &*self.tensor.header;
            let ptr = header.data_ptr as *mut T;
            std::slice::from_raw_parts_mut(ptr, header.data_len as usize)
        }
    }
}

impl<'a, T> Drop for TensorRefMut<'a, T> {
    fn drop(&mut self) {
        unsafe {
            (*self.tensor.header).unborrow_mut();
        }
    }
}
