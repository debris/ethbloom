//! 
//! ```rust
//! extern crate ethbloom;
//! extern crate rustc_hex;
//! use rustc_hex::FromHex;
//! use ethbloom::{Bloom, Input};
//!
//! fn main() {
//! 	let bloom: Bloom = "00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
//! 	let address = "ef2d6d194084c2de36e0dabfce45d046b37d1106".from_hex().unwrap();
//! 	let topic = "02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc".from_hex().unwrap();
//! 	
//! 	let mut my_bloom = Bloom::default();
//! 	assert!(!my_bloom.contains(Input::Raw(&address)));
//! 	assert!(!my_bloom.contains(Input::Raw(&topic)));
//!
//! 	my_bloom.accrue(Input::Raw(&address));
//! 	assert!(my_bloom.contains(Input::Raw(&address)));
//! 	assert!(!my_bloom.contains(Input::Raw(&topic)));
//! 	
//! 	my_bloom.accrue(Input::Raw(&topic));
//! 	assert!(my_bloom.contains(Input::Raw(&address)));
//! 	assert!(my_bloom.contains(Input::Raw(&topic)));
//! 	assert_eq!(my_bloom, bloom);
//! 	}
//! ```
//!

extern crate tiny_keccak;
extern crate rustc_hex;

use std::{ops, fmt, mem, str};
use tiny_keccak::keccak256;
use rustc_hex::{ToHex, FromHex, FromHexError};

// 3 according to yellowpaper
const BLOOM_BITS: u32 = 3;

/// Returns log2.
fn log2(x: usize) -> u32 {
	if x <= 1 {
		return 0;
	}

	let n = x.leading_zeros();
	mem::size_of::<usize>() as u32 * 8 - n
}

pub enum Input<'a> {
	Raw(&'a [u8]),
	Hash(&'a [u8; 32]),
}

enum Hash<'a> {
	Ref(&'a [u8; 32]),
	Owned([u8; 32]),
}

impl<'a> From<Input<'a>> for Hash<'a> {
	fn from(input: Input<'a>) -> Self {
		match input {
			Input::Raw(raw) => Hash::Owned(keccak256(raw)),
			Input::Hash(hash) => Hash::Ref(hash),
		}
	}
}

impl<'a> ops::Index<usize> for Hash<'a> {
	type Output = u8;

	fn index(&self, index: usize) -> &u8 {
		match *self {
			Hash::Ref(r) => &r[index],
			Hash::Owned(ref hash) => &hash[index],
		}
	}
}

impl<'a> Hash<'a> {
	fn len(&self) -> usize {
		match *self {
			Hash::Ref(r) => r.len(),
			Hash::Owned(ref hash) => hash.len(),
		}
	}
}

pub struct Bloom {
	data: [u8; 256],
}

impl Default for Bloom {
	fn default() -> Self {
		Bloom {
			data: [0u8; 256],
		}
	}
}

impl str::FromStr for Bloom {
	type Err = FromHexError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut result = Bloom::default();
		let hex = s.from_hex()?;
		if hex.len() != result.data.len() {
			return Err(FromHexError::InvalidHexLength);
		}
		result.data.copy_from_slice(&hex);
		Ok(result)
	}
}

impl PartialEq for Bloom {
	fn eq(&self, other: &Self) -> bool {
		let s_ref: &[u8] = &self.data;
		let o_ref: &[u8] = &other.data;
		s_ref.eq(o_ref)
	}
}

impl<'a> PartialEq<BloomRef<'a>> for Bloom {
	fn eq(&self, other: &BloomRef<'a>) -> bool {
		let s_ref: &[u8] = &self.data;
		let o_ref: &[u8] = other.data;
		s_ref.eq(o_ref)
	}
}

impl Clone for Bloom {
	fn clone(&self) -> Self {
		let mut result = Bloom::default();
		result.data.copy_from_slice(&self.data);
		result
	}
}

impl fmt::Debug for Bloom {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Bloom")
			.field("data", &self.data.to_hex())
			.finish()
	}
}

impl fmt::Display for Bloom {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.data.to_hex())
	}
}

impl<'a> From<Input<'a>> for Bloom {
	fn from(input: Input<'a>) -> Bloom {
		let mut bloom = Bloom::default();
		bloom.accrue(input);
		bloom
	}
}

impl From<&'static str> for Bloom {
	fn from(s: &'static str) -> Bloom {
		s.parse().expect("&'static str to be valid Bloom")
	}
}

impl From<Bloom> for [u8; 256] {
	fn from(bloom: Bloom) -> [u8; 256] {
		bloom.data
	}
}

impl Bloom {
	pub fn is_empty(&self) -> bool {
		self.data.iter().all(|x| *x == 0)
	}

	pub fn contains<'a>(&self, input: Input<'a>) -> bool {
		let bloom: Bloom = input.into();
		self.contains_bloom(&bloom)
	}

	pub fn contains_bloom<'a, B>(&self, bloom: B) -> bool where BloomRef<'a>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		// workaround for https://github.com/rust-lang/rust/issues/43644
		self.contains_bloom_ref(bloom_ref)
	}

	fn contains_bloom_ref(&self, bloom: BloomRef) -> bool {
		let self_ref: BloomRef = self.into();
		self_ref.contains_bloom(bloom)
	}

	pub fn accrue<'a>(&mut self, input: Input<'a>) {
		let p = BLOOM_BITS;

		let m = self.data.len();
		let bloom_bits = m * 8;
		let mask = bloom_bits - 1;
		let bloom_bytes = (log2(bloom_bits) + 7) / 8;

		let hash: Hash = input.into();

		// must be a power of 2
		assert_eq!(m & (m - 1), 0);
		// out of range
		assert!(p * bloom_bytes <= hash.len() as u32);

		let mut ptr = 0;

		for _ in 0..p {
			let mut index = 0 as usize;
			for _ in 0..bloom_bytes {
				index = (index << 8) | hash[ptr] as usize;
				ptr += 1;
			}
			index &= mask;
			self.data[m - 1 - index / 8] |= 1 << (index % 8);
		}
	}

	pub fn accrue_bloom<'a, B>(&mut self, bloom: B) where BloomRef<'a>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		assert_eq!(self.data.len(), 256);
		assert_eq!(bloom_ref.data.len(), 256);
		for i in 0..self.data.len() {
			self.data[i] |= bloom_ref.data[i];
		}
	}

	pub fn data(&self) -> &[u8; 256] {
		&self.data
	}
}

#[derive(Clone, Copy)]
pub struct BloomRef<'a> {
	data: &'a [u8; 256],
}

impl<'a> BloomRef<'a> {
	pub fn is_empty(&self) -> bool {
		self.data.iter().all(|x| *x == 0)
	}

	pub fn contains<'b>(&self, input: Input<'b>) -> bool {
		let bloom: Bloom = input.into();
		self.contains_bloom(&bloom)
	}
	
	pub fn contains_bloom<'b, B>(&self, bloom: B) -> bool where BloomRef<'b>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		assert_eq!(self.data.len(), 256);
		assert_eq!(bloom_ref.data.len(), 256);
		for i in 0..self.data.len() {
			let a = self.data[i];
			let b = bloom_ref.data[i];
			if (a & b) != b {
				return false;
			}
		}
		true
	}

	pub fn data(&self) -> &'a [u8; 256] {
		self.data
	}
}

impl<'a> From<&'a [u8; 256]> for BloomRef<'a> {
	fn from(data: &'a [u8; 256]) -> Self {
		BloomRef {
			data: data
		}
	}
}

impl<'a> From<&'a Bloom> for BloomRef<'a> {
	fn from(bloom: &'a Bloom) -> Self {
		BloomRef {
			data: &bloom.data
		}
	}
}

#[cfg(test)]
mod tests {
	use rustc_hex::FromHex;
	use {Bloom, Input};

    #[test]
    fn it_works() {
		let bloom: Bloom = "00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
		let address = "ef2d6d194084c2de36e0dabfce45d046b37d1106".from_hex().unwrap();
		let topic = "02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc".from_hex().unwrap();

		let mut my_bloom = Bloom::default();
		assert!(!my_bloom.contains(Input::Raw(&address)));
		assert!(!my_bloom.contains(Input::Raw(&topic)));

		my_bloom.accrue(Input::Raw(&address));
		assert!(my_bloom.contains(Input::Raw(&address)));
		assert!(!my_bloom.contains(Input::Raw(&topic)));

		my_bloom.accrue(Input::Raw(&topic));
		assert!(my_bloom.contains(Input::Raw(&address)));
		assert!(my_bloom.contains(Input::Raw(&topic)));
		assert_eq!(my_bloom, bloom);
    }
}
