#![feature(test)]

extern crate test;

#[macro_use]
extern crate crunchy;

use test::Bencher;

#[bench]
fn forwards_with_crunchy(b: &mut Bencher) {
	let mut data = [0u8; 256];
	let other_data = [1u8; 256];

	b.iter(|| {
		unroll! {
				for i in 0..255 {
					data[i] |= other_data[i];
				}
			}
	})
}

#[bench]
fn backwards_with_crunchy(b: &mut Bencher) {
	let mut data = [0u8; 256];
	let other_data = [1u8; 256];

	b.iter(|| {
		unroll! {
				for i in 0..255 {
					data[255-i] |= other_data[255-i];
				}
			}
	})
}


#[bench]
fn forwards_without_crunchy(b: &mut Bencher) {
	let mut data = [0u8; 256];
	let other_data = [1u8; 256];

	b.iter(|| {
		for i in 0..255 {
			data[i] |= other_data[i];
		}
	})
}

#[bench]
fn backwards_without_crunchy(b: &mut Bencher) {
	let mut data = [0u8; 256];
	let other_data = [1u8; 256];

	b.iter(|| {
		for i in 0..255 {
			data[255-i] |= other_data[255-i];
		}
	})
}
