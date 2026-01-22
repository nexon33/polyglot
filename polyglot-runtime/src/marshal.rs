//! Type marshaling utilities

use crate::Result;

/// Generic trait for marshaling to foreign languages
pub trait Marshal<T> {
    fn marshal(&self) -> Result<T>;
}

/// Generic trait for unmarshaling from foreign languages  
pub trait Unmarshal<T>: Sized {
    fn unmarshal(value: T) -> Result<Self>;
}
