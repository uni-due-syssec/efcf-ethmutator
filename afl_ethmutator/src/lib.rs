// Copyright 2021 Michael Rodler
// This file is part of ethmutator.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate ethmutator;
extern crate libc;

use ethmutator::EthMutator;
use libc::{c_char, c_int, c_uint, c_void, size_t};
use std::ffi::OsString;

/* AFL++ mutator API:

void *afl_custom_init(afl_state_t *afl, unsigned int seed);
unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size);
size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size);
const char *afl_custom_describe(void *data, size_t max_description_len);
size_t afl_custom_post_process(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf);
int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size);
size_t afl_custom_trim(void *data, unsigned char **out_buf);
int afl_custom_post_trim(void *data, unsigned char success);
size_t afl_custom_havoc_mutation(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t max_size);
unsigned char afl_custom_havoc_mutation_probability(void *data);
unsigned char afl_custom_queue_get(void *data, const unsigned char *filename);
void afl_custom_queue_new_entry(void *data, const unsigned char *filename_new_queue, const unsigned int *filename_orig_queue);
const char* afl_custom_introspection(my_mutator_t *data);
void afl_custom_deinit(void *data);

*/

#[no_mangle]
pub extern "C" fn afl_custom_init(_: *const c_void, seed: c_uint) -> *mut EthMutator {
    let mut state = if let Some(path) = std::env::var_os("CONTRACT_ABI") {
        if let Some(p) = path.to_str() {
            if p.contains(",") {
                let paths: Vec<OsString> = p.split(",").map(|x| OsString::from(x)).collect();
                match EthMutator::from_multi_abi_file(paths) {
                    Ok(m) => m,
                    Err(e) => panic!(
                        "failed to read multiple ABIs from CONTRACT_ABI={:?} error: {}",
                        path, e
                    ),
                }
            } else {
                match EthMutator::from_abi_file(&path) {
                    Ok(m) => m,
                    Err(e) => panic!("failed to read CONTRACT_ABI={:?} error: {}", path, e),
                }
            }
        } else {
            match EthMutator::from_abi_file(&path) {
                Ok(m) => m,
                Err(e) => panic!("failed to read CONTRACT_ABI={:?} error: {}", path, e),
            }
        }
    } else {
        EthMutator::new()
    };

    // seed the RNG with the AFL provided value
    state.seed(seed as u64);

    // we try to load a contract specific dictionary
    if let Some(path) = std::env::var_os("CONTRACT_DICT") {
        match state.load_dict_from_file(&path) {
            Ok(_) => {}
            Err(e) => panic!("failed to read CONTRACT_DICT={:?} error: {}", path, e),
        }
    }

    let state = Box::new(state);
    Box::into_raw(state)
}

/// ```c
/// uint8_t afl_custom_queue_get(void *data, const uint8_t *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn afl_custom_queue_get(
    mutator: *mut EthMutator,
    filename: *const c_char,
) -> u8 {
    let rfilename = std::ffi::CStr::from_ptr(filename);
    (*mutator).cache_filename(rfilename.into());
    // always return true and always fuzz
    1
}

/// ```c
/// unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size);
/// ```
#[no_mangle]
pub unsafe extern "C" fn afl_custom_fuzz_count(
    mutator: *mut EthMutator,
    buf: *const u8,
    buf_size: size_t,
    preferred_rounds: u32,
) -> c_uint {
    let buf_slice = std::slice::from_raw_parts(buf, buf_size);
    let stage_count = (*mutator).start_round(buf_slice, preferred_rounds as usize);
    stage_count as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_fuzz(
    mutator: *mut EthMutator,
    _buf: *mut u8,
    _buf_size: size_t,
    out_buf: *mut *const u8,
    _add_buf: *mut u8,
    _add_buf_size: size_t,
    max_size: size_t,
) -> size_t {
    //let buf_slice = std::slice::from_raw_parts(buf, buf_size);

    (*mutator).mutate_round();
    let x = (*mutator).current_buffer();

    *out_buf = x.as_ptr();
    if x.len() <= max_size {
        x.len()
    } else {
        max_size
    }
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_deinit(data: *mut EthMutator) {
    let _ = Box::from_raw(data);
    // this then drops state at the end of the function
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_describe(
    data: *mut EthMutator,
    max_description_len: size_t,
) -> *const c_char {
    if (*data).describe_string().len() < max_description_len {
        (*data).describe_string().as_ptr() as *const c_char
    } else {
        panic!(
            "oh no. AFL++ told us the maximum description length is {}, but we want to use {}",
            max_description_len,
            (*data).describe_string().len()
        );
        //0 as *const c_char
    }
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_introspection(data: *mut EthMutator) -> *const c_char {
    (*data).format_stages_as_string();
    let p = (*data).obtain_stages_string().as_ptr();
    p
}

#[cfg(not(feature = "afl-custom-trim"))]
mod afl_custom_splice {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn afl_custom_queue_new_entry(
        mutator: *mut EthMutator,
        filename_new_queue: *const c_char,
        _filename_orig_queue: *const c_char,
    ) {
        // for every new queue entry, we try to read the file and store the parsed version in our
        // custom mutator. This allows us to perform our custom splicing mutation in the custom
        // mutator.
        use std::os::unix::ffi::OsStrExt;
        let file_new = std::ffi::CStr::from_ptr(filename_new_queue);
        let file_new = file_new.to_bytes();
        let file_new = std::ffi::OsStr::from_bytes(file_new);
        match std::fs::read(file_new) {
            Ok(bytes) => {
                (*mutator).push_to_queue(&bytes);
            }
            Err(e) => {
                println!("failed to read file {:?} error {:?}", file_new, e)
            }
        }
    }
}

/// **Warning** currently this feature causes a segfault and is not usable...
///
/// TODO: identify why this causes AFL++ to segfault due to an issue with malloc?
#[cfg(feature = "afl-custom-havoc")]
mod afl_custom_havoc {
    use super::*;

    /// Original C prototype:
    /// ```c
    /// size_t afl_custom_havoc_mutation(
    ///     void *data,
    ///     unsigned char *buf,
    ///     size_t buf_size,
    ///     unsigned char **out_buf,
    ///     size_t max_size);
    /// ```
    #[no_mangle]
    pub unsafe extern "C" fn afl_custom_havoc_mutation(
        mutator: *mut EthMutator,
        buf: *mut u8,
        buf_size: size_t,
        out_buf: *mut *const u8,
        max_size: size_t,
    ) -> size_t {
        let buf_slice = std::slice::from_raw_parts(buf, buf_size);

        (*mutator).mutate_bytes_one(&buf_slice);
        let x = (*mutator).current_buffer();

        *out_buf = x.as_ptr();
        if x.len() <= max_size {
            x.len()
        } else {
            max_size
        }
    }

    /// original C prototype:
    /// ```c
    /// unsigned char afl_custom_havoc_mutation_probability(void *data);
    /// ```
    pub unsafe extern "C" fn afl_custom_havoc_mutation_probability(
        _mutator: *mut EthMutator,
    ) -> u8 {
        15
    }
}

#[cfg(feature = "afl-custom-trim")]
mod afl_trim {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn afl_custom_init_trim(
        mutator: *mut EthMutator,
        buf: *mut u8,
        buf_size: size_t,
    ) -> i32 {
        let buf_slice = std::slice::from_raw_parts(buf, buf_size);

        let t = (*mutator).init_trim(buf_slice) as i32;
        if (*mutator).current_trim_buffer().len() > buf_size {
            // this is a special case here, where the fuzzer gave us a too small input to trim;
            // parsing the input will result in default values for the required blockheader. As
            // such, the size of the parsed input will be bigger than the actual input bytes
            // provided by the fuzzer. So we just bail out early here by returning 0 trimming steps
            // to AFL.
            0
        } else {
            t
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn afl_custom_trim(
        mutator: *mut EthMutator,
        out_buf: *mut *const u8,
    ) -> size_t {
        let r = (*mutator).trim_step();
        let x = (*mutator).current_trim_buffer();
        *out_buf = x.as_ptr();
        r
    }

    #[no_mangle]
    pub unsafe extern "C" fn afl_custom_post_trim(mutator: *mut EthMutator, success: c_int) -> i32 {
        (*mutator).trim_status(success > 0) as i32
    }
}
