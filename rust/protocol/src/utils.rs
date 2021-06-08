//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use prost;

use std::cmp::Ordering;

// prost documents the only possible encoding error is if there is insufficient
// space, which is not a problem when it is allowed to encode into a Vec
pub(crate) fn no_encoding_error<M: prost::Message>(m: M) -> Box<[u8]> {
    let mut result = Vec::new();
    m.encode(&mut result)
        .expect("no prost error encoding into a Vec");
    result.into_boxed_slice()
}

fn expand_top_bit(a: u8) -> u8 {
    //if (a >> 7) == 1 { 0xFF } else { 0 }
    0u8.wrapping_sub(a >> 7)
}

fn ct_is_zero(a: u8) -> u8 {
    //if a == 0 { 0xFF } else { 0 }
    expand_top_bit(!a & a.wrapping_sub(1))
}

fn ct_is_eq(a: u8, b: u8) -> u8 {
    //if a == b { 0xFF } else { 0 }
    ct_is_zero(a ^ b)
}

fn ct_is_lt(a: u8, b: u8) -> u8 {
    //if a < b { 0xFF } else { 0 }
    expand_top_bit(a ^ ((a ^ b) | ((a.wrapping_sub(b)) ^ a)))
}

fn ct_select(mask: u8, a: u8, b: u8) -> u8 {
    debug_assert!(mask == 0 || mask == 0xFF);
    //if mask == 0xFF { a } else if mask == 0x00 { b } else { unreachable!(); }
    b ^ (mask & (a ^ b))
}

/// Compare the contents of `x` and `y` while trying not to leak information to [timing
/// attacks](https://en.wikipedia.org/wiki/Timing_attack).
///
/// The primary goal of this function is to **not leak any additional information, besides the
/// ordering, about the value of the two keys**, say due to an early exit of the loop.
///
/// ### Example usage
///```
/// # use libsignal_protocol::utils_unstable::*;
/// use std::cmp::Ordering;
///
/// // Equality checking is the most significant use case for this function.
/// assert!(Ordering::Equal == constant_time_cmp(b"abc", b"abc"));
/// // But we can also use it to order keys lexicographically.
/// assert!(Ordering::Less == constant_time_cmp(b"ab", b"bc"));
/// assert!(Ordering::Greater == constant_time_cmp(b"c", b"a"));
///```
///
/// ### Implementation Notes
/// #### Leaked Information
/// 1. If x and y are different lengths, this leaks information about their relative sizes.
///     - *This is currently irrelevant, as we always invoke it with two inputs of the same size.*
/// 2. In addition, it will leak the final comparison result, when the integer is translated to the
///    Ordering enum.
///     - *This seems unavoidable.*
///
/// #### Possible Improvements
/// - It would be possible to instead have this function SHA-256 hash both
///   inputs, then compare the resulting hashes in the usual non-constant
///   time way.
///     - *We avoid this approach at the moment since it is not clear if applications will rely on
///       public key ordering being defined in some particular way or not.*
pub fn constant_time_cmp(x: &[u8], y: &[u8]) -> Ordering {
    if x.len() < y.len() {
        return Ordering::Less;
    }
    if x.len() > y.len() {
        return Ordering::Greater;
    }

    let mut result: u8 = 0;

    for i in 0..x.len() {
        let a = x[x.len() - 1 - i];
        let b = y[x.len() - 1 - i];

        let is_eq = ct_is_eq(a, b);
        let is_lt = ct_is_lt(a, b);

        result = ct_select(is_eq, result, ct_select(is_lt, 1, 255));
    }

    debug_assert!(result == 0 || result == 1 || result == 255);

    if result == 0 {
        Ordering::Equal
    } else if result == 1 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_cmp() {
        use rand::Rng;

        assert_eq!(constant_time_cmp(&[1], &[1]), Ordering::Equal);
        assert_eq!(constant_time_cmp(&[0, 1], &[1]), Ordering::Greater);
        assert_eq!(constant_time_cmp(&[1], &[0, 1]), Ordering::Less);
        assert_eq!(constant_time_cmp(&[2], &[1, 0, 1]), Ordering::Less);

        let mut rng = rand::rngs::OsRng;
        for len in 1..320 {
            let x: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let y: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let expected = x.cmp(&y);
            let result = constant_time_cmp(&x, &y);
            assert_eq!(result, expected);

            let expected = y.cmp(&x);
            let result = constant_time_cmp(&y, &x);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(0), 0xFF);

        for i in 1..255 {
            assert_eq!(ct_is_zero(i), 0x00);
        }
    }

    #[test]
    fn test_ct_is_lt() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x < y { 0xFF } else { 0 };
                let result = ct_is_lt(x, y);
                assert_eq!(result, expected);
            }
        }
    }

    #[test]
    fn test_ct_is_eq() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x == y { 0xFF } else { 0 };
                let result = ct_is_eq(x, y);
                assert_eq!(result, expected);
            }
        }
    }
}
