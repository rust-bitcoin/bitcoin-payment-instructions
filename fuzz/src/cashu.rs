// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! We have quite a bit of logic in our cashu instruction decoder which is hard to reach from the
//! outside because of the bech32 checksum. Instead, here, we fuzz it directly skipping the bech32
//! check.

use bitcoin_payment_instructions::cashu::*;

#[inline]
pub fn do_test(mut data: &[u8]) {
	if let Ok(req) = CashuPaymentRequest::from_bytes_fuzzy(data) {
		match req.to_bech32_string() {
			Ok(reencoded) => {
				let re_decoded = CashuPaymentRequest::from_bech32_string(&reencoded).unwrap();
				assert_eq!(re_decoded, req);
			},
			Err(e) => assert_eq!(e, Error::Bech32),
		}
	}
}

pub fn cashu_test(data: &[u8]) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn cashu_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
