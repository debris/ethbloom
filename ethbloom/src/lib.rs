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

impl<'a, 'b> ops::BitAnd<&'b [u8; 256]> for &'a Bloom {
	type Output = Bloom;
	
	fn bitand(self, rhs: &'b [u8; 256]) -> Self::Output {
		let mut result = Bloom::default();
		for i in 0..self.data.len() {
			result.data[i] = self.data[i] & rhs[i];
		}
		result
	}
}

impl<'a, 'b> ops::BitAnd<&'b Bloom> for &'a Bloom {
	type Output = Bloom;
	
	fn bitand(self, rhs: &'b Bloom) -> Self::Output {
		self.bitand(&rhs.data)
	}
}

impl<'a, 'b> ops::BitAnd<BloomRef<'b>> for &'a Bloom {
	type Output = Bloom;
	
	fn bitand(self, rhs: BloomRef<'b>) -> Self::Output {
		self.bitand(rhs.data)
	}
}

impl<'a, 'b> ops::BitAnd<BloomRef<'b>> for BloomRef<'a> {
	type Output = Bloom;
	
	fn bitand(self, rhs: BloomRef<'b>) -> Self::Output {
		let mut result = Bloom::default();
		for i in 0..self.data.len() {
			result.data[i] = self.data[i] & rhs.data[i];
		}
		result
	}
}

impl<'a, 'b> ops::BitOr<&'b Bloom> for &'a Bloom {
	type Output = Bloom;
	
	fn bitor(self, rhs: &'b Bloom) -> Self::Output {
		let mut result = Bloom::default();
		for i in 0..self.data.len() {
			result.data[i] = self.data[i] | rhs.data[i];
		}
		result
	}
}

impl<'a, 'b> ops::BitOr<Input<'b>> for &'a Bloom {
	type Output = Bloom;

	fn bitor(self, rhs: Input<'b>) -> Self::Output {
		let bloom: Bloom = rhs.into();
		&bloom | self
	}
}

impl<'a> From<Input<'a>> for Bloom {
	fn from(input: Input<'a>) -> Bloom {
		let p = BLOOM_BITS;

		let mut result = Bloom::default();

		let m = result.data.len();
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
			result.data[m - 1 - index / 8] |= 1 << (index % 8);
		}

		result
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
		self.contains_bloom(bloom)
	}

	pub fn contains_bloom<B: AsBloomRef>(&self, bloom: B) -> bool {
		let bloom_ref = bloom.as_bloom_ref();
		(self & bloom_ref) == bloom_ref
	}

	pub fn accrue<'a>(&mut self, input: Input<'a>) {
		*self = (self as &Self) | input;
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
		self.contains_bloom(bloom)
	}
	
	pub fn contains_bloom<B: AsBloomRef>(&self, bloom: B) -> bool {
		let bloom_ref = bloom.as_bloom_ref();
		(*self & bloom_ref) == bloom_ref
	}

	pub fn data(&self) -> &'a [u8; 256] {
		self.data
	}
}

pub trait AsBloomRef {
	fn as_bloom_ref(&self) -> BloomRef;
}

impl AsBloomRef for Bloom {
	fn as_bloom_ref(&self) -> BloomRef {
		BloomRef {
			data: &self.data
		}
	}
}

impl<'a> AsBloomRef for &'a Bloom {
	fn as_bloom_ref(&self) -> BloomRef {
		BloomRef {
			data: &self.data
		}
	}
}

impl<'a> AsBloomRef for BloomRef<'a> {
	fn as_bloom_ref(&self) -> BloomRef {
		*self
	}
}

impl<'a> AsBloomRef for &'a [u8; 256] {
	fn as_bloom_ref(&self) -> BloomRef {
		BloomRef {
			data: *self
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
