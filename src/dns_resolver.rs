//! A [`HrnResolver`] which uses any recursive DNS resolver to resolve Human Readable Names into
//! bitcoin payment instructions.

use std::boxed::Box;
use std::net::SocketAddr;

use dnssec_prover::query::build_txt_proof_async;
use dnssec_prover::rr::Name;

use crate::amount::Amount;
use crate::dnssec_utils::resolve_proof;
use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};

/// An [`HrnResolver`] which resolves BIP 353 Human Readable Names to payment instructions using a
/// configured recursive DNS resolver.
///
/// Note that using this reveals who we're paying to the recursive DNS resolver. For improved
/// privacy, consider proxying the request over Tor.
pub struct DNSHrnResolver(pub SocketAddr);

impl DNSHrnResolver {
	async fn resolve_dns(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", hrn.user(), hrn.domain()))
				.map_err(|_| "The provided HRN was too long to fit in a DNS name")?;

		let err = "DNS resolution failed";
		let proof = build_txt_proof_async(self.0, &dns_name).await.map_err(|_| err)?;

		resolve_proof(&dns_name, proof.0)
	}
}

impl HrnResolver for DNSHrnResolver {
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async move { self.resolve_dns(hrn).await })
	}

	fn resolve_lnurl<'a>(&'a self, _: String, _: Amount, _: [u8; 32]) -> LNURLResolutionFuture<'a> {
		let err = "resolve_lnurl shouldn't be called when we don't reoslve LNURL";
		debug_assert!(false, "{}", err);
		Box::pin(async move { Err(err) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	#[tokio::test]
	async fn test_dns_hrn_resolver() {
		let resolver = DNSHrnResolver(SocketAddr::from_str("8.8.8.8:53").unwrap());
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
}
