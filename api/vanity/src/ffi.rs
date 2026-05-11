/// FFI interface — C ABI exported symbols for Python (ctypes / cffi).
///
/// # Memory contract
///
/// All strings returned to the caller are heap-allocated C strings (null-terminated).
/// The caller **must** free them with `vanity_free_string`.  Failing to do so leaks
/// memory.
///
/// # Thread safety
///
/// `vanity_find` is blocking and may spawn rayon threads internally.
/// It is safe to call from multiple Python threads as long as the GIL is released
/// before the call (e.g. via `ctypes` with `restype` set).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_ulonglong};

use crate::parallel::find_vanity_address_full;
use crate::matcher::{Matcher, MatchMode};

/// Opaque result handle returned to the caller.
///
/// Layout (all fields are null-terminated C strings):
/// ```c
/// typedef struct {
///     char *address;       // bech32m SP address
///     char *scan_priv;     // scan  private key, lowercase hex (64 chars)
///     char *spend_priv;    // spend private key, lowercase hex (64 chars)
///     unsigned long long attempts;
/// } VanityFfiResult;
/// ```
#[repr(C)]
pub struct VanityFfiResult {
    pub address:    *mut c_char,
    pub scan_priv:  *mut c_char,
    pub spend_priv: *mut c_char,
    pub attempts:   c_ulonglong,
}

/// Search for a vanity Silent Payment address.
///
/// # Parameters
/// * `pattern`      – null-terminated UTF-8 vanity string to search for
/// * `mode`         – 0 = contains (default), 1 = prefix (after HRP), 2 = suffix
/// * `num_threads`  – worker threads (0 = all logical CPUs)
/// * `testnet`      – 0 = mainnet ("sp"), non-zero = testnet ("tsp")
///
/// # Returns
/// A heap-allocated `VanityFfiResult`.  Free with `vanity_free_result`.
/// Returns NULL on invalid input (e.g. NULL pattern).
///
/// # Safety
/// `pattern` must be a valid null-terminated C string for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn vanity_find(
    pattern:     *const c_char,
    mode:        c_int,
    num_threads: c_int,
    testnet:     c_int,
) -> *mut VanityFfiResult {
    if pattern.is_null() {
        return std::ptr::null_mut();
    }

    let pat_str = match CStr::from_ptr(pattern).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let match_mode = match mode {
        1 => MatchMode::Prefix,
        2 => MatchMode::Suffix,
        _ => MatchMode::Contains,
    };

    let matcher     = Matcher::new(pat_str, match_mode);
    let threads     = num_threads.max(0) as usize;
    let hrp         = if testnet != 0 { "tsp" } else { "sp" };

    let result = find_vanity_address_full(matcher, threads, hrp, 0);

    let address    = CString::new(result.address).unwrap();
    let scan_priv  = CString::new(hex::encode(result.key_material.scan_priv)).unwrap();
    let spend_priv = CString::new(hex::encode(result.key_material.spend_priv)).unwrap();

    let out = Box::new(VanityFfiResult {
        address:    address.into_raw(),
        scan_priv:  scan_priv.into_raw(),
        spend_priv: spend_priv.into_raw(),
        attempts:   result.attempts,
    });

    Box::into_raw(out)
}

/// Free a `VanityFfiResult` previously returned by `vanity_find`.
///
/// # Safety
/// `ptr` must be a pointer returned by `vanity_find` and must not have been
/// freed already.
#[no_mangle]
pub unsafe extern "C" fn vanity_free_result(ptr: *mut VanityFfiResult) {
    if ptr.is_null() {
        return;
    }
    let r = Box::from_raw(ptr);
    // Retake ownership of the C strings so they are dropped properly.
    if !r.address.is_null()    { drop(CString::from_raw(r.address));    }
    if !r.scan_priv.is_null()  { drop(CString::from_raw(r.scan_priv));  }
    if !r.spend_priv.is_null() { drop(CString::from_raw(r.spend_priv)); }
}

/// Free a raw C string returned by this library (currently unused externally,
/// but provided for completeness).
///
/// # Safety
/// `ptr` must be a pointer returned by this library.
#[no_mangle]
pub unsafe extern "C" fn vanity_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}