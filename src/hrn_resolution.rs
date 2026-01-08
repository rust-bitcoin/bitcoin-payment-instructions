//! When encountering human-readable names of the form alice@domain, we should attempt to resolve
//! them into concrete payment instructions which wallets can handle.
//!
//! Currently, this generally is done either using BIP 353 and the DNS or using LNURL-Pay and
//! LN-Address. Because these could be resolved using different methods (and, for privacy reasons
//! some wallets may wish to avoid LNURL), we abstract the resolution process using the trait and
//! associated types in this module.

use crate::amount::Amount;

use lightning_invoice::Bolt11Invoice;

pub use lightning::onion_message::dns_resolution::HumanReadableName;

use core::future::Future;
use core::pin::Pin;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug)]
/// The first-step resolution of a Human Readable Name.
///
/// It can either represent a resolution using BIP 353 and the DNS or the first step resolution of
/// an LNURL-Pay. The second step, resolving a callback URI to a [`Bolt11Invoice`] occurs via
/// [`HrnResolver::resolve_lnurl`].
pub enum HrnResolution {
	/// The HRN was resolved using BIP 353 and the DNS. The result should contain a BIP 321
	/// bitcoin: URI as well as a DNSSEC proof which allows later verification of the payment
	/// instructions.
	DNSSEC {
		/// A DNSSEC proof as used in BIP 353.
		///
		/// If the HRN was resolved using BIP 353, this should be set to a full proof which can later
		/// be copied to PSBTs for hardware wallet verification or stored as a part of proof of
		/// payment.
		proof: Option<Vec<u8>>,
		/// The result of the resolution.
		///
		/// This should contain a string which can be parsed as further payment instructions. For a BIP
		/// 353 resolution, this will contain a full BIP 321 bitcoin: URI, for a LN-Address resolution
		/// this will contain a lightning BOLT 11 invoice.
		result: String,
	},
	/// The HRN was resolved using LNURL-Pay as an LN-Address. The result contains a callback URI
	/// which will be used once we pick an amount to fetch a final [`Bolt11Invoice`].
	LNURLPay {
		/// The minimum amount which can be sent to the recipient, as specified in the LNURL-Pay
		/// initial response.
		min_value: Amount,
		/// The maximum amount which can be sent to the recipient, as specified in the LNURL-Pay
		/// initial response.
		max_value: Amount,
		/// The description hash which must appear in the final [`Bolt11Invoice`], committing to
		/// the full recipient metadata.
		///
		/// While we could store the full recipient metadata and use it as a committed value in our
		/// proof-of-payment, there is no way to ensure it is actually provable against the
		/// server/initial payment instructions string because the server can return a
		/// [`Bolt11Invoice`] signed by any arbitrary public key.
		expected_description_hash: [u8; 32],
		/// The text/plain description provided in the LNURL-Pay initial response.
		///
		/// This is generally human-readable and can be displayed to the user as with any other
		/// recipient description in payment instructions.
		recipient_description: Option<String>,
		/// The callback URI which can be used, with a concrete amount, to fetch a final
		/// [`Bolt11Invoice`] which can be paid.
		callback: String,
	},
}

/// A future which resolves to a [`HrnResolution`].
pub type HrnResolutionFuture<'a> =
	Pin<Box<dyn Future<Output = Result<HrnResolution, &'static str>> + Send + 'a>>;

/// A future which resolves to a [`Bolt11Invoice`].
pub type LNURLResolutionFuture<'a> =
	Pin<Box<dyn Future<Output = Result<Bolt11Invoice, &'static str>> + Send + 'a>>;

/// An arbitrary resolver for a Human Readable Name.
///
/// In general, such a resolver should first attempt to resolve using DNSSEC as defined in BIP 353.
///
/// For clients that also support LN-Address, if the BIP 353 resolution fails they should then fall
/// back to LN-Address to resolve to a Lightning BOLT 11 using HTTP.
///
/// A resolver which uses any (DNSSEC-enabled) recursive DNS resolver to resolve BIP 353 HRNs is
/// provided in
#[cfg_attr(feature = "std", doc = "[`dns_resolver::DNSHrnResolver`]")]
#[cfg_attr(not(feature = "std"), doc = "`dns_resolver::DNSHrnResolver`")]
/// if the crate is built with the `std` feature. Note that using this reveals who we are paying to
/// the recursive DNS resolver.
///
/// A resolver which uses HTTPS to `dns.google` and HTTPS to arbitrary servers for LN-Address is
/// provided in
#[cfg_attr(feature = "http", doc = "[`http_resolver::HTTPHrnResolver`]")]
#[cfg_attr(not(feature = "http"), doc = "`http_resolver::HTTPHrnResolver`")]
/// if this crate is built with the `http` feature. Note that using this generally reveals our IP
/// address to recipients,  as well as potentially who we are paying to Google.
///
#[cfg_attr(
	feature = "std",
	doc = "[`dns_resolver::DNSHrnResolver`]: crate::dns_resolver::DNSHrnResolver"
)]
#[cfg_attr(
	feature = "http",
	doc = "[`http_resolver::HTTPHrnResolver`]: crate::http_resolver::HTTPHrnResolver"
)]
pub trait HrnResolver {
	/// Resolves the given Human Readable Name into a [`HrnResolution`] containing a result which
	/// can be further parsed as payment instructions.
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a>;

	/// Resolves the given Lnurl into a [`HrnResolution`] containing a result which
	/// can be further parsed as payment instructions.
	fn resolve_lnurl<'a>(&'a self, url: &'a str) -> HrnResolutionFuture<'a>;

	/// Resolves the LNURL callback (from a [`HrnResolution::LNURLPay`]) into a [`Bolt11Invoice`].
	///
	/// This shall only be called if [`Self::resolve_hrn`] returns an [`HrnResolution::LNURLPay`].
	fn resolve_lnurl_to_invoice<'a>(
		&'a self, callback_url: String, amount: Amount, expected_description_hash: [u8; 32],
	) -> LNURLResolutionFuture<'a>;
}

/// An HRN "resolver" that never succeeds at resolving.
#[derive(Clone, Copy)]
pub struct DummyHrnResolver;

impl HrnResolver for DummyHrnResolver {
	fn resolve_hrn<'a>(&'a self, _hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async { Err("Human Readable Name resolution not supported") })
	}

	fn resolve_lnurl<'a>(&'a self, _lnurl: &'a str) -> HrnResolutionFuture<'a> {
		Box::pin(async { Err("LNURL resolution not supported") })
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, _: String, _: Amount, _: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		Box::pin(async { Err("LNURL resolution not supported") })
	}
}
