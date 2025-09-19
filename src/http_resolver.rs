//! A [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
//! Names into bitcoin payment instructions.

use std::boxed::Box;
use std::fmt::Write;
use std::str::FromStr;

use serde::Deserialize;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash as _;

use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::{Name, TXT_TYPE};

use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};

use crate::amount::Amount;
use crate::dnssec_utils::resolve_proof;
use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};

const DOH_ENDPOINT: &'static str = "https://dns.google/dns-query?dns=";

/// An [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
/// Names into bitcoin payment instructions.
///
/// Note that using this may reveal our IP address to the recipient and information about who we're
/// paying to Google (via `dns.google`).
#[derive(Debug, Clone)]
pub struct HTTPHrnResolver {
	client: reqwest::Client,
}

impl HTTPHrnResolver {
	/// Create a new `HTTPHrnResolver` with a default `reqwest::Client`.
	pub fn new() -> Self {
		HTTPHrnResolver::default()
	}

	/// Create a new `HTTPHrnResolver` with a custom `reqwest::Client`.
	pub fn with_client(client: reqwest::Client) -> Self {
		HTTPHrnResolver { client }
	}
}

impl Default for HTTPHrnResolver {
	fn default() -> Self {
		HTTPHrnResolver { client: reqwest::Client::new() }
	}
}

/// The "URL and Filename safe" Base64 Alphabet from RFC 4648
const B64_CHAR: [u8; 64] = [
	b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
	b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f',
	b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v',
	b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'-', b'_',
];

#[rustfmt::skip]
fn write_base64(mut bytes: &[u8], out: &mut String) {
	while bytes.len() >= 3 {
		let (byte_a, byte_b, byte_c) = (bytes[0] as usize, bytes[1] as usize, bytes[2] as usize);
		out.push(B64_CHAR[ (byte_a & 0b1111_1100) >> 2] as char);
		out.push(B64_CHAR[((byte_a & 0b0000_0011) << 4) | ((byte_b & 0b1111_0000) >> 4)] as char);
		out.push(B64_CHAR[((byte_b & 0b0000_1111) << 2) | ((byte_c & 0b1100_0000) >> 6)] as char);
		out.push(B64_CHAR[  byte_c & 0b0011_1111] as char);
		bytes = &bytes[3..];
	}
	match bytes.len() {
		2 => {
			let (byte_a, byte_b, byte_c) = (bytes[0] as usize, bytes[1] as usize, 0usize);
			out.push(B64_CHAR[ (byte_a & 0b1111_1100) >> 2] as char);
			out.push(B64_CHAR[((byte_a & 0b0000_0011) << 4) | ((byte_b & 0b1111_0000) >> 4)] as char);
			out.push(B64_CHAR[((byte_b & 0b0000_1111) << 2) | ((byte_c & 0b1100_0000) >> 6)] as char);
		},
		1 => {
			let (byte_a, byte_b) = (bytes[0] as usize, 0usize);
			out.push(B64_CHAR[ (byte_a & 0b1111_1100) >> 2] as char);
			out.push(B64_CHAR[((byte_a & 0b0000_0011) << 4) | ((byte_b & 0b1111_0000) >> 4)] as char);
		},
		_ => debug_assert_eq!(bytes.len(), 0),
	}
}

fn query_to_url(query: QueryBuf) -> String {
	let base64_len = (query.len() * 8 + 5) / 6;
	let mut query_string = String::with_capacity(base64_len + DOH_ENDPOINT.len());

	query_string += DOH_ENDPOINT;
	write_base64(&query[..], &mut query_string);

	debug_assert_eq!(query_string.len(), base64_len + DOH_ENDPOINT.len());

	query_string
}

#[derive(Deserialize)]
struct LNURLInitResponse {
	callback: String,
	#[serde(rename = "maxSendable")]
	max_sendable: u64,
	#[serde(rename = "minSendable")]
	min_sendable: u64,
	metadata: String,
	tag: String,
}

#[derive(Deserialize)]
struct LNURLMetadata(Vec<(String, String)>);

#[derive(Deserialize)]
struct LNURLCallbackResponse {
	pr: String,
	routes: Vec<String>,
}

const DNS_ERR: &'static str = "DNS Request to dns.google failed";

impl HTTPHrnResolver {
	async fn resolve_dns(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", hrn.user(), hrn.domain()))
				.map_err(|_| "The provided HRN was too long to fit in a DNS name")?;
		let (mut proof_builder, initial_query) = ProofBuilder::new(&dns_name, TXT_TYPE);
		let mut pending_queries = vec![initial_query];

		while let Some(query) = pending_queries.pop() {
			let request_url = query_to_url(query);
			let req =
				self.client.get(request_url).header("accept", "application/dns-message").build();
			let resp = self.client.execute(req.map_err(|_| DNS_ERR)?).await.map_err(|_| DNS_ERR)?;
			let body = resp.bytes().await.map_err(|_| DNS_ERR)?;

			let mut answer = QueryBuf::new_zeroed(0);
			answer.extend_from_slice(&body[..]);
			match proof_builder.process_response(&answer) {
				Ok(queries) => {
					for query in queries {
						pending_queries.push(query);
					}
				},
				Err(_) => {
					return Err(DNS_ERR);
				},
			}
		}

		let err = "Too many queries required to build proof";
		let proof = proof_builder.finish_proof().map(|(proof, _ttl)| proof).map_err(|()| err)?;

		resolve_proof(&dns_name, proof)
	}

	async fn resolve_lnurl_impl(&self, lnurl_url: &str) -> Result<HrnResolution, &'static str> {
		let err = "Failed to fetch LN-Address initial well-known endpoint";
		let init_result = self.client.get(lnurl_url).send().await.map_err(|_| err)?;
		let init: LNURLInitResponse = init_result.json().await.map_err(|_| err)?;

		if init.tag != "payRequest" {
			return Err("LNURL initial init_response had an incorrect tag value");
		}
		if init.min_sendable > init.max_sendable {
			return Err("LNURL initial init_response had no sendable amounts");
		}

		let err = "LNURL metadata was not in the correct format";
		let metadata: LNURLMetadata = serde_json::from_str(&init.metadata).map_err(|_| err)?;
		let mut recipient_description = None;
		for (ty, value) in metadata.0 {
			if ty == "text/plain" {
				recipient_description = Some(value);
			}
		}
		let expected_description_hash = Sha256::hash(init.metadata.as_bytes()).to_byte_array();
		Ok(HrnResolution::LNURLPay {
			min_value: Amount::from_milli_sats(init.min_sendable)
				.map_err(|_| "LNURL initial response had a minimum amount greater than 21M BTC")?,
			max_value: Amount::from_milli_sats(init.max_sendable).unwrap_or(Amount::MAX),
			callback: init.callback,
			expected_description_hash,
			recipient_description,
		})
	}
}

impl HrnResolver for HTTPHrnResolver {
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async move {
			// First try to resolve the HRN using BIP 353 DNSSEC proof building
			match self.resolve_dns(hrn).await {
				Ok(r) => Ok(r),
				Err(e) if e == DNS_ERR => {
					// If we got an error that might indicate the recipient doesn't support BIP
					// 353, try LN-Address via LNURL
					let init_url =
						format!("https://{}/.well-known/lnurlp/{}", hrn.domain(), hrn.user());
					self.resolve_lnurl(&init_url).await
				},
				Err(e) => Err(e),
			}
		})
	}

	fn resolve_lnurl<'a>(&'a self, url: &'a str) -> HrnResolutionFuture<'a> {
		Box::pin(async move { self.resolve_lnurl_impl(url).await })
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, mut callback: String, amt: Amount, expected_description_hash: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		Box::pin(async move {
			let err = "LN-Address callback failed";
			if callback.contains('?') {
				write!(&mut callback, "&amount={}", amt.milli_sats()).expect("Write to String");
			} else {
				write!(&mut callback, "?amount={}", amt.milli_sats()).expect("Write to String");
			}
			let http_response = self.client.get(callback).send().await.map_err(|_| err)?;
			let response: LNURLCallbackResponse = http_response.json().await.map_err(|_| err)?;

			if !response.routes.is_empty() {
				return Err("LNURL callback response contained a non-empty routes array");
			}

			let invoice = Bolt11Invoice::from_str(&response.pr).map_err(|_| err)?;
			if invoice.amount_milli_satoshis() != Some(amt.milli_sats()) {
				return Err("LNURL callback response contained an invoice with the wrong amount");
			}
			match invoice.description() {
				Bolt11InvoiceDescriptionRef::Hash(hash) => {
					if hash.0.as_byte_array() != &expected_description_hash {
						Err("Incorrect invoice description hash")
					} else {
						Ok(invoice)
					}
				},
				Bolt11InvoiceDescriptionRef::Direct(_) => {
					Err("BOLT 11 invoice resolved via LNURL must have a matching description hash")
				},
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	fn to_base64(bytes: &[u8]) -> String {
		let expected_len = (bytes.len() * 8 + 5) / 6;
		let mut res = String::with_capacity(expected_len);
		write_base64(bytes, &mut res);
		assert_eq!(res.len(), expected_len);
		res
	}

	#[test]
	fn test_base64() {
		// RFC 4648
		assert_eq!(&to_base64(b"f"), "Zg");
		assert_eq!(&to_base64(b"fo"), "Zm8");
		assert_eq!(&to_base64(b"foo"), "Zm9v");
		assert_eq!(&to_base64(b"foob"), "Zm9vYg");
		assert_eq!(&to_base64(b"fooba"), "Zm9vYmE");
		assert_eq!(&to_base64(b"foobar"), "Zm9vYmFy");
		// Wikipedia
		assert_eq!(
			&to_base64(b"Many hands make light work."),
			"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
		);
		assert_eq!(&to_base64(b"Man"), "TWFu");
	}

	#[tokio::test]
	async fn test_dns_via_http_hrn_resolver() {
		let resolver = HTTPHrnResolver::default();
		let instructions = PaymentInstructions::parse(
			"send.some@satsto.me",
			bitcoin::Network::Bitcoin,
			&resolver,
			true,
		)
		.await
		.unwrap();

		let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
			assert_eq!(instr.min_amt(), None);
			assert_eq!(instr.max_amt(), None);

			assert_eq!(instr.pop_callback(), None);
			assert!(instr.bip_353_dnssec_proof().is_some());

			let hrn = instr.human_readable_name().as_ref().unwrap();
			assert_eq!(hrn.user(), "send.some");
			assert_eq!(hrn.domain(), "satsto.me");

			instr.set_amount(Amount::from_sats(100_000).unwrap(), &resolver).await.unwrap()
		} else {
			panic!();
		};

		assert_eq!(resolved.pop_callback(), None);
		assert!(resolved.bip_353_dnssec_proof().is_some());

		let hrn = resolved.human_readable_name().as_ref().unwrap();
		assert_eq!(hrn.user(), "send.some");
		assert_eq!(hrn.domain(), "satsto.me");

		for method in resolved.methods() {
			match method {
				PaymentMethod::LightningBolt11(_) => {
					panic!("Should only have static payment instructions");
				},
				PaymentMethod::LightningBolt12(_) => {},
				PaymentMethod::OnChain { .. } => {},
			}
		}
	}

	#[tokio::test]
	async fn test_http_hrn_resolver() {
		let resolver = HTTPHrnResolver::default();
		let instructions = PaymentInstructions::parse(
			"lnurltest@bitcoin.ninja",
			bitcoin::Network::Bitcoin,
			&resolver,
			true,
		)
		.await
		.unwrap();

		let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
			assert!(instr.min_amt().is_some());
			assert!(instr.max_amt().is_some());

			assert_eq!(instr.pop_callback(), None);
			assert!(instr.bip_353_dnssec_proof().is_none());

			let hrn = instr.human_readable_name().as_ref().unwrap();
			assert_eq!(hrn.user(), "lnurltest");
			assert_eq!(hrn.domain(), "bitcoin.ninja");

			instr.set_amount(Amount::from_sats(100_000).unwrap(), &resolver).await.unwrap()
		} else {
			panic!();
		};

		assert_eq!(resolved.pop_callback(), None);
		assert!(resolved.bip_353_dnssec_proof().is_none());

		let hrn = resolved.human_readable_name().as_ref().unwrap();
		assert_eq!(hrn.user(), "lnurltest");
		assert_eq!(hrn.domain(), "bitcoin.ninja");

		for method in resolved.methods() {
			match method {
				PaymentMethod::LightningBolt11(invoice) => {
					assert_eq!(invoice.amount_milli_satoshis(), Some(100_000_000));
				},
				PaymentMethod::LightningBolt12(_) => panic!("Should only resolve to BOLT 11"),
				PaymentMethod::OnChain(_) => panic!("Should only resolve to BOLT 11"),
			}
		}
	}

	#[tokio::test]
	async fn test_http_lnurl_resolver() {
		let resolver = HTTPHrnResolver::default();
		let instructions = PaymentInstructions::parse(
			// lnurl encoding for lnurltest@bitcoin.ninja
			"lnurl1dp68gurn8ghj7cnfw33k76tw9ehxjmn2vyhjuam9d3kz66mwdamkutmvde6hymrs9akxuatjd36x2um5ahcq39",
			Network::Bitcoin,
			&resolver,
			true,
		)
		.await
		.unwrap();

		let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
			assert!(instr.min_amt().is_some());
			assert!(instr.max_amt().is_some());

			assert_eq!(instr.pop_callback(), None);
			assert!(instr.bip_353_dnssec_proof().is_none());

			instr.set_amount(Amount::from_sats(100_000).unwrap(), &resolver).await.unwrap()
		} else {
			panic!();
		};

		assert_eq!(resolved.pop_callback(), None);
		assert!(resolved.bip_353_dnssec_proof().is_none());

		for method in resolved.methods() {
			match method {
				PaymentMethod::LightningBolt11(invoice) => {
					assert_eq!(invoice.amount_milli_satoshis(), Some(100_000_000));
				},
				PaymentMethod::LightningBolt12(_) => panic!("Should only resolve to BOLT 11"),
				PaymentMethod::OnChain(_) => panic!("Should only resolve to BOLT 11"),
			}
		}
	}
}
