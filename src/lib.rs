//! These days, there are many possible ways to communicate Bitcoin payment instructions.
//! This crate attempts to unify them into a simple parser which can read text provided directly by
//! a payer or via a QR code scan/URI open and convert it into payment instructions.
//!
//! This crate doesn't actually help you *pay* these instructions, but provides a unified way to
//! parse them.
//!
//! Payment instructions come in two versions -
//!  * [`ConfigurableAmountPaymentInstructions`] represent instructions which can be paid with a
//!    configurable amount, but may require further resolution to convert them into a
//!    [`FixedAmountPaymentInstructions`] for payment.
//!  * [`FixedAmountPaymentInstructions`] represent instructions for which the recipient wants a
//!    specific quantity of funds and needs no further resolution
//!
//! In general, you should resolve a string (received either from a QR code scan, a system URI open
//! call, a "recipient" text box, or a pasted "recipient" instruction) through
//! [`PaymentInstructions::parse`].
//!
//! From there, if you receive a [`PaymentInstructions::FixedAmount`] you should check that you
//! support at least one of the [`FixedAmountPaymentInstructions::methods`] and request approval
//! from the wallet owner to complete the payment.
//!
//! If you receive a [`PaymentInstructions::ConfigurableAmount`] instead, you should similarly
//! check that that you support one of the [`ConfigurableAmountPaymentInstructions::methods`] using
//! [`PossiblyResolvedPaymentMethod::method_type`], then display an amount selection UI to the
//! wallet owner. Once they've selected an amount, you should proceed with
//! [`ConfigurableAmountPaymentInstructions::set_amount`] to fetch a finalized
//! [`FixedAmountPaymentInstructions`] before moving to confirmation and payment.

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use alloc::borrow::ToOwned;
use alloc::str::FromStr;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use bitcoin::{address, Address, Network};
use core::time::Duration;
use lightning::offers::offer::{self, Offer};
use lightning::offers::parse::Bolt12ParseError;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, ParseOrSemanticError};

#[cfg(feature = "std")]
mod dnssec_utils;

#[cfg(feature = "std")]
pub mod dns_resolver;

#[cfg(feature = "http")]
pub mod http_resolver;

#[cfg(feature = "std")] // TODO: Drop once we upgrade to LDK 0.2
pub mod onion_message_resolver;

pub mod amount;

pub mod receive;

pub mod cashu;

pub mod hrn_resolution;

use amount::Amount;
use hrn_resolution::{HrnResolution, HrnResolver, HumanReadableName};

/// A method which can be used to make a payment
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentMethod {
	/// A payment using lightning as described by the given BOLT 11 invoice.
	LightningBolt11(Bolt11Invoice),
	/// A payment using lightning as described by the given BOLT 12 offer.
	LightningBolt12(Offer),
	/// A payment directly on-chain to the specified address.
	OnChain(Address),
	/// A payment using Cashu as described by the given NUT-26 payment request.
	Cashu(cashu::CashuPaymentRequest),
}

impl PaymentMethod {
	fn amount(&self) -> Option<Amount> {
		match self {
			PaymentMethod::LightningBolt11(invoice) => {
				invoice.amount_milli_satoshis().map(|amt_msat| {
					let res = Amount::from_milli_sats(amt_msat);
					debug_assert!(res.is_ok(), "This should be rejected at parse-time");
					res.unwrap_or(Amount::ZERO)
				})
			},
			PaymentMethod::LightningBolt12(offer) => match offer.amount() {
				Some(offer::Amount::Bitcoin { amount_msats }) => {
					let res = Amount::from_milli_sats(amount_msats);
					debug_assert!(res.is_ok(), "This should be rejected at parse-time");
					Some(res.unwrap_or(Amount::ZERO))
				},
				Some(offer::Amount::Currency { .. }) => None,
				None => None,
			},
			PaymentMethod::OnChain(_) => None,
			PaymentMethod::Cashu(req) => match req.unit {
				Some(cashu::CurrencyUnit::Sat) => {
					req.amount.and_then(|a| Amount::from_sats(a).ok())
				},
				Some(cashu::CurrencyUnit::Msat) => {
					req.amount.and_then(|a| Amount::from_milli_sats(a).ok())
				},
				_ => None,
			},
		}
	}

	fn is_lightning(&self) -> bool {
		match self {
			PaymentMethod::LightningBolt11(_) => true,
			PaymentMethod::LightningBolt12(_) => true,
			PaymentMethod::OnChain(_) => false,
			PaymentMethod::Cashu(_) => false,
		}
	}

	fn has_fixed_amount(&self) -> bool {
		match self {
			PaymentMethod::LightningBolt11(invoice) => invoice.amount_milli_satoshis().is_some(),
			PaymentMethod::LightningBolt12(offer) => match offer.amount() {
				Some(offer::Amount::Bitcoin { .. }) => true,
				Some(offer::Amount::Currency { .. }) => true,
				None => false,
			},
			PaymentMethod::OnChain(_) => false,
			PaymentMethod::Cashu(req) => req.amount.is_some(),
		}
	}
}

/// A payment method which may require further resolution once the amount we wish to pay is fixed.
pub enum PossiblyResolvedPaymentMethod<'a> {
	/// A payment using lightning as described by a BOLT 11 invoice which will be provided by this
	/// LNURL-pay endpoint
	LNURLPay {
		/// The minimum value the recipient will accept payment for.
		min_value: Amount,
		/// The maximum value the recipient will accept payment for.
		max_value: Amount,
		/// The URI which must be fetched (once an `amount` parameter is added) to fully resolve
		/// this into a [`Bolt11Invoice`].
		callback: &'a str,
	},
	/// A payment method which has been fully resolved.
	Resolved(&'a PaymentMethod),
}

/// The method that a [`PossiblyResolvedPaymentMethod`] will eventually resolve to.
///
/// This is useful to determine if you support the required payment mechanism for a
/// [`ConfigurableAmountPaymentInstructions`] before you display an amount selector to the wallet
/// owner.
pub enum PaymentMethodType {
	/// The [`PossiblyResolvedPaymentMethod`] will eventually resolve to a
	/// [`PaymentMethod::LightningBolt11`].
	LightningBolt11,
	/// The [`PossiblyResolvedPaymentMethod`] will eventually resolve to a
	/// [`PaymentMethod::LightningBolt12`].
	LightningBolt12,
	/// The [`PossiblyResolvedPaymentMethod`] will eventually resolve to a
	/// [`PaymentMethod::OnChain`].
	OnChain,
	/// The [`PossiblyResolvedPaymentMethod`] will eventually resolve to a
	/// [`PaymentMethod::Cashu`].
	Cashu,
}

impl<'a> PossiblyResolvedPaymentMethod<'a> {
	/// Fetches the [`PaymentMethodType`] that this payment method will ultimately resolve to.
	pub fn method_type(&self) -> PaymentMethodType {
		match self {
			Self::LNURLPay { .. } => PaymentMethodType::LightningBolt11,
			Self::Resolved(PaymentMethod::LightningBolt11(_)) => PaymentMethodType::LightningBolt11,
			Self::Resolved(PaymentMethod::LightningBolt12(_)) => PaymentMethodType::LightningBolt12,
			Self::Resolved(PaymentMethod::OnChain(_)) => PaymentMethodType::OnChain,
			Self::Resolved(PaymentMethod::Cashu(_)) => PaymentMethodType::Cashu,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct PaymentInstructionsImpl {
	description: Option<String>,
	methods: Vec<PaymentMethod>,
	ln_amt: Option<Amount>,
	cashu_amt: Option<Amount>,
	onchain_amt: Option<Amount>,
	lnurl: Option<(String, [u8; 32], Amount, Amount)>,
	pop_callback: Option<String>,
	hrn: Option<HumanReadableName>,
	hrn_proof: Option<Vec<u8>>,
}

/// Defines common accessors for payment instructions in relation to [`PaymentInstructionsImpl`]
macro_rules! common_methods {
	($struct: ty) => {
		impl $struct {
			/// A recipient-provided description of the payment instructions.
			///
			/// This may be:
			///  * the `label` or `message` parameter in a BIP 321 bitcoin: URI
			///  * the `description` field in a lightning BOLT 11 invoice
			///  * the `description` field in a lightning BOLT 12 offer
			#[inline]
			pub fn recipient_description(&self) -> Option<&str> {
				self.inner().description.as_ref().map(|d| d.as_str())
			}

			/// Fetches the proof-of-payment callback URI.
			///
			/// Once a payment has been completed, the proof-of-payment (hex-encoded payment preimage for a
			/// lightning BOLT 11 invoice, raw transaction serialized in hex for on-chain payments,
			/// not-yet-defined for lightning BOLT 12 invoices) must be appended to this URI and the URI
			/// opened with the default system URI handler.
			#[inline]
			pub fn pop_callback(&self) -> Option<&str> {
				self.inner().pop_callback.as_ref().map(|c| c.as_str())
			}

			/// Fetches the [`HumanReadableName`] which was resolved, if the resolved payment instructions
			/// were for a Human Readable Name.
			#[inline]
			pub fn human_readable_name(&self) -> &Option<HumanReadableName> {
				&self.inner().hrn
			}

			/// Fetches the BIP 353 DNSSEC proof which was used to resolve these payment instructions, if
			/// they were resolved from a HumanReadable Name using BIP 353.
			///
			/// This proof should be included in any PSBT output (as type `PSBT_OUT_DNSSEC_PROOF`)
			/// generated using these payment instructions.
			///
			/// It should also be stored to allow us to later prove that this payment was made to
			/// [`Self::human_readable_name`].
			#[inline]
			pub fn bip_353_dnssec_proof(&self) -> &Option<Vec<u8>> {
				&self.inner().hrn_proof
			}
		}
	};
}

/// Parsed payment instructions representing a set of possible ways to pay a fixed quantity to a
/// recipient, as well as some associated metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FixedAmountPaymentInstructions {
	inner: PaymentInstructionsImpl,
}

impl FixedAmountPaymentInstructions {
	/// The maximum amount any payment instruction requires payment for.
	///
	/// If `None`, the only available payment method requires payment in a currency other than
	/// sats, requiring currency conversion to determine the amount required.
	///
	/// Note that we may allow different [`Self::methods`] to have slightly different amounts (e.g.
	/// if a recipient wishes to be paid more for on-chain payments to offset their future fees),
	/// but only up to [`MAX_AMOUNT_DIFFERENCE`].
	pub fn max_amount(&self) -> Option<Amount> {
		[self.inner.ln_amt, self.inner.onchain_amt, self.inner.cashu_amt]
			.into_iter()
			.flatten()
			.max()
	}

	/// The amount which the payment instruction requires payment for when paid over lightning.
	///
	/// We require that all lightning payment methods in payment instructions require an identical
	/// amount for payment, and thus if this method returns `None` it indicates either:
	///  * no lightning payment instructions exist,
	///  * the only lightning payment instructions are for a BOLT 12 offer denominated in a
	///    non-Bitcoin currency.
	///
	/// Note that if this object was built by resolving a [`ConfigurableAmountPaymentInstructions`]
	/// with [`set_amount`] on a lightning BOLT 11 or BOLT 12 invoice-containing instruction, this
	/// will return `Some` but the [`Self::methods`] with [`PaymentMethod::LightningBolt11`] or
	/// [`PaymentMethod::LightningBolt12`] may still contain instructions without amounts.
	///
	/// [`set_amount`]: ConfigurableAmountPaymentInstructions::set_amount
	pub fn ln_payment_amount(&self) -> Option<Amount> {
		self.inner.ln_amt
	}

	/// The amount which the payment instruction requires payment for when paid via Cashu.
	///
	/// We require that all Cashu payment methods in payment instructions require an identical
	/// amount for payment.
	pub fn cashu_payment_amount(&self) -> Option<Amount> {
		self.inner.cashu_amt
	}

	/// The amount which the payment instruction requires payment for when paid on-chain.
	///
	/// Will return `None` if no on-chain payment instructions are available.
	///
	/// There is no way to encode different payment amounts for multiple on-chain formats
	/// currently, and as such all on-chain [`PaymentMethod`]s are for the same amount.
	pub fn onchain_payment_amount(&self) -> Option<Amount> {
		self.inner.onchain_amt
	}

	/// The list of [`PaymentMethod`]s.
	#[inline]
	pub fn methods(&self) -> &[PaymentMethod] {
		&self.inner.methods
	}

	fn inner(&self) -> &PaymentInstructionsImpl {
		&self.inner
	}
}

common_methods!(FixedAmountPaymentInstructions);

/// Parsed payment instructions representing a set of possible ways to pay a configurable quantity
/// of Bitcoin, as well as some associated metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigurableAmountPaymentInstructions {
	inner: PaymentInstructionsImpl,
}

impl ConfigurableAmountPaymentInstructions {
	/// The minimum amount which the recipient will accept payment for, if provided as a part of
	/// the payment instructions.
	pub fn min_amt(&self) -> Option<Amount> {
		self.inner.lnurl.as_ref().map(|(_, _, a, _)| *a)
	}

	/// The minimum amount which the recipient will accept payment for, if provided as a part of
	/// the payment instructions.
	pub fn max_amt(&self) -> Option<Amount> {
		self.inner.lnurl.as_ref().map(|(_, _, _, a)| *a)
	}

	/// The supported list of [`PossiblyResolvedPaymentMethod`].
	///
	/// See [`PossiblyResolvedPaymentMethod::method_type`] for the specific payment protocol which
	/// each payment method will ultimately resolve to.
	#[inline]
	pub fn methods<'a>(&'a self) -> impl Iterator<Item = PossiblyResolvedPaymentMethod<'a>> {
		let res = self.inner().methods.iter().map(PossiblyResolvedPaymentMethod::Resolved);
		res.chain(self.inner().lnurl.iter().map(|(callback, _, min, max)| {
			PossiblyResolvedPaymentMethod::LNURLPay { callback, min_value: *min, max_value: *max }
		}))
	}

	/// Resolve the configurable amount to a fixed amount and create a
	/// [`FixedAmountPaymentInstructions`].
	///
	/// May resolve LNURL-Pay instructions that were created from an LN-Address Human Readable
	/// Name into a lightning [`Bolt11Invoice`].
	///
	/// Note that for lightning BOLT 11 or BOLT 12 instructions, we cannot modify the invoice/offer
	/// itself and thus cannot set a specific amount on the [`PaymentMethod::LightningBolt11`] or
	/// [`PaymentMethod::LightningBolt12`] inner fields themselves. Still,
	/// [`FixedAmountPaymentInstructions::ln_payment_amount`] will return the value provided in
	/// `amount`.
	pub async fn set_amount<R: HrnResolver>(
		self, amount: Amount, resolver: &R,
	) -> Result<FixedAmountPaymentInstructions, &'static str> {
		let mut inner = self.inner;
		if let Some((callback, expected_desc_hash, min, max)) = inner.lnurl.take() {
			if amount < min || amount > max {
				return Err("Amount was not within the min_amt/max_amt bounds");
			}
			debug_assert!(inner.methods.is_empty());
			debug_assert!(inner.onchain_amt.is_none());
			debug_assert!(inner.cashu_amt.is_none());
			debug_assert!(inner.pop_callback.is_none());
			debug_assert!(inner.hrn_proof.is_none());
			let bolt11 =
				resolver.resolve_lnurl_to_invoice(callback, amount, expected_desc_hash).await?;
			if bolt11.amount_milli_satoshis() != Some(amount.milli_sats()) {
				return Err("LNURL resolution resulted in a BOLT 11 invoice with the wrong amount");
			}
			inner.methods = vec![PaymentMethod::LightningBolt11(bolt11)];
			inner.ln_amt = Some(amount);
		} else {
			if inner.methods.iter().any(|meth| matches!(meth, PaymentMethod::OnChain(_))) {
				let amt = Amount::from_milli_sats((amount.milli_sats() + 999) / 1000)
					.map_err(|_| "Requested amount was too close to 21M sats to round up")?;
				inner.onchain_amt = Some(amt);
			}
			if inner.methods.iter().any(|meth| meth.is_lightning()) {
				inner.ln_amt = Some(amount);
			}
			if inner.methods.iter().any(|meth| matches!(meth, PaymentMethod::Cashu(_))) {
				inner.cashu_amt = Some(amount);
			}
		}
		Ok(FixedAmountPaymentInstructions { inner })
	}

	fn inner(&self) -> &PaymentInstructionsImpl {
		&self.inner
	}
}

common_methods!(ConfigurableAmountPaymentInstructions);

/// Parsed payment instructions representing a set of possible ways to pay, as well as some
/// associated metadata.
///
/// Currently we can resolve the following strings into payment instructions:
///  * BIP 321 bitcoin: URIs
///  * Lightning BOLT 11 invoices (optionally with the lightning: URI prefix)
///  * Lightning BOLT 12 offers
///  * On-chain addresses
///  * BIP 353 human-readable names in the name@domain format.
///  * LN-Address human-readable names in the name@domain format.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PaymentInstructions {
	/// The payment instructions support a variable amount which must be selected prior to payment.
	///
	/// In general, you should first check that you support some of the payment methods by calling
	/// [`PossiblyResolvedPaymentMethod::method_type`] on each method in
	/// [`ConfigurableAmountPaymentInstructions::methods`], then request the intended amount from
	/// the wallet owner and build the final instructions using
	/// [`ConfigurableAmountPaymentInstructions::set_amount`].
	ConfigurableAmount(ConfigurableAmountPaymentInstructions),
	/// The payment instructions support only payment for specific amount(s) given by
	/// [`FixedAmountPaymentInstructions::ln_payment_amount`] and
	/// [`FixedAmountPaymentInstructions::onchain_payment_amount`] (which are within
	/// [`MAX_AMOUNT_DIFFERENCE`] of each other).
	FixedAmount(FixedAmountPaymentInstructions),
}

common_methods!(PaymentInstructions);

impl PaymentInstructions {
	fn inner(&self) -> &PaymentInstructionsImpl {
		match self {
			PaymentInstructions::ConfigurableAmount(inner) => &inner.inner,
			PaymentInstructions::FixedAmount(inner) => &inner.inner,
		}
	}
}

/// The maximum amount requested that we will allow individual payment methods to differ in
/// satoshis.
///
/// If any [`PaymentMethod`] is for an amount different by more than this amount from another
/// [`PaymentMethod`], we will consider it a [`ParseError::InconsistentInstructions`].
pub const MAX_AMOUNT_DIFFERENCE: Amount = Amount::from_sats_panicy(100);

/// An error when parsing payment instructions into [`PaymentInstructions`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ParseError {
	/// An invalid lightning BOLT 11 invoice was encountered
	InvalidBolt11(ParseOrSemanticError),
	/// An invalid lightning BOLT 12 offer was encountered
	InvalidBolt12(Bolt12ParseError),
	/// An invalid on-chain address was encountered
	InvalidOnChain(address::ParseError),
	/// An invalid Cashu payment request was encountered
	InvalidCashu(cashu::Error),
	/// An invalid lnurl was encountered
	InvalidLnurl(&'static str),
	/// The payment instructions encoded instructions for a network other than the one specified.
	WrongNetwork,
	/// Different parts of the payment instructions were inconsistent.
	///
	/// A developer-readable error string is provided, though you may or may not wish to provide
	/// this directly to users.
	InconsistentInstructions(&'static str),
	/// The instructions were invalid due to a semantic error.
	///
	/// A developer-readable error string is provided, though you may or may not wish to provide
	/// this directly to users.
	InvalidInstructions(&'static str),
	/// The payment instructions did not appear to match any known form of payment instructions.
	UnknownPaymentInstructions,
	/// The BIP 321 bitcoin: URI included unknown required parameter(s)
	UnknownRequiredParameter,
	/// The call to [`HrnResolver::resolve_hrn`] failed with the contained error.
	HrnResolutionError(&'static str),
	/// The payment instructions have expired and are no longer payable.
	InstructionsExpired,
}

fn check_expiry(_expiry: Duration) -> Result<(), ParseError> {
	#[cfg(feature = "std")]
	{
		use std::time::SystemTime;
		if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
			if now > _expiry {
				return Err(ParseError::InstructionsExpired);
			}
		}
	}
	Ok(())
}

struct Bolt11Amounts {
	ln_amount: Option<Amount>,
	fallbacks_amount: Option<Amount>,
}

fn instructions_from_bolt11(
	invoice: Bolt11Invoice, network: Network,
) -> Result<(Option<String>, Bolt11Amounts, impl Iterator<Item = PaymentMethod>), ParseError> {
	if invoice.network() != network {
		return Err(ParseError::WrongNetwork);
	}
	if let Some(expiry) = invoice.expires_at() {
		check_expiry(expiry)?;
	}

	let fallbacks = invoice.fallback_addresses().into_iter().map(PaymentMethod::OnChain);

	let mut fallbacks_amount = None;
	let mut ln_amount = None;
	if let Some(amt_msat) = invoice.amount_milli_satoshis() {
		let err = "BOLT 11 invoice required an amount greater than 21M BTC";
		ln_amount = Some(
			Amount::from_milli_sats(amt_msat).map_err(|_| ParseError::InvalidInstructions(err))?,
		);
		if !invoice.fallbacks().is_empty() {
			fallbacks_amount = Some(
				Amount::from_sats((amt_msat + 999) / 1000)
					.map_err(|_| ParseError::InvalidInstructions(err))?,
			);
		}
	}

	let amounts = Bolt11Amounts { ln_amount, fallbacks_amount };

	if let Bolt11InvoiceDescriptionRef::Direct(desc) = invoice.description() {
		Ok((
			Some(desc.as_inner().0.clone()),
			amounts,
			Some(PaymentMethod::LightningBolt11(invoice)).into_iter().chain(fallbacks),
		))
	} else {
		Ok((
			None,
			amounts,
			Some(PaymentMethod::LightningBolt11(invoice)).into_iter().chain(fallbacks),
		))
	}
}

fn check_offer(offer: Offer, net: Network) -> Result<(Option<String>, PaymentMethod), ParseError> {
	if !offer.supports_chain(net.chain_hash()) {
		return Err(ParseError::WrongNetwork);
	}
	if let Some(expiry) = offer.absolute_expiry() {
		check_expiry(expiry)?;
	}
	let description = offer.description().map(|desc| desc.0.to_owned());
	if let Some(offer::Amount::Bitcoin { amount_msats }) = offer.amount() {
		if Amount::from_milli_sats(amount_msats).is_err() {
			let err = "BOLT 12 offer requested an amount greater than 21M BTC";
			return Err(ParseError::InvalidInstructions(err));
		}
	}
	Ok((description, PaymentMethod::LightningBolt12(offer)))
}

// What str.split_once() should do...
fn split_once(haystack: &str, needle: char) -> (&str, Option<&str>) {
	haystack.split_once(needle).map(|(a, b)| (a, Some(b))).unwrap_or((haystack, None))
}

fn un_percent_encode(encoded: &str) -> Result<String, ParseError> {
	let mut res = Vec::with_capacity(encoded.len());
	let mut iter = encoded.bytes();
	let err = "A Proof of Payment URI was not properly %-encoded in a BIP 321 bitcoin: URI";
	while let Some(b) = iter.next() {
		if b == b'%' {
			let high = iter.next().ok_or(ParseError::InvalidInstructions(err))?;
			let low = iter.next().ok_or(ParseError::InvalidInstructions(err))?;
			if !high.is_ascii_digit() || !low.is_ascii_digit() {
				return Err(ParseError::InvalidInstructions(err));
			}
			res.push(((high - b'0') << 4) | (low - b'0'));
		} else {
			res.push(b);
		}
	}
	String::from_utf8(res).map_err(|_| ParseError::InvalidInstructions(err))
}

#[test]
fn test_un_percent_encode() {
	assert_eq!(un_percent_encode("%20").unwrap(), " ");
	assert_eq!(un_percent_encode("42%20 ").unwrap(), "42  ");
	assert!(un_percent_encode("42%2").is_err());
	assert!(un_percent_encode("42%2a").is_err());
}

fn parse_resolved_instructions(
	instructions: &str, network: Network, supports_proof_of_payment_callbacks: bool,
	hrn: Option<HumanReadableName>, hrn_proof: Option<Vec<u8>>,
) -> Result<PaymentInstructions, ParseError> {
	let (uri_proto, uri_suffix) = split_once(instructions, ':');

	if uri_proto.eq_ignore_ascii_case("bitcoin") {
		let (body, params) = split_once(uri_suffix.unwrap_or(""), '?');
		let mut methods = Vec::new();
		let mut description = None;
		let mut pop_callback = None;
		if !body.is_empty() {
			let addr = Address::from_str(body).map_err(ParseError::InvalidOnChain)?;
			let address = addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
			methods.push(PaymentMethod::OnChain(address));
		}
		if let Some(params) = params {
			let mut onchain_amt = None;
			for param in params.split('&') {
				let (k, v) = split_once(param, '=');

				let mut parse_segwit = |pfx| {
					if let Some(address_string) = v {
						if address_string.is_char_boundary(3)
							&& !address_string[..3].eq_ignore_ascii_case(pfx)
						{
							// `bc`/`tb` key-values must only include bech32/bech32m strings with
							// HRP "bc"/"tb" (i.e. mainnet/testnet Segwit addresses).
							let err = "BIP 321 bitcoin: URI contained a bc/tb instruction which was not a Segwit address (bc1*/tb1*)";
							return Err(ParseError::InvalidInstructions(err));
						}
						let addr = Address::from_str(address_string)
							.map_err(ParseError::InvalidOnChain)?;
						let address =
							addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
						methods.push(PaymentMethod::OnChain(address));
					} else {
						let err = "BIP 321 bitcoin: URI contained a bc (Segwit address) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
					Ok(())
				};
				if k.eq_ignore_ascii_case("bc") || k.eq_ignore_ascii_case("req-bc") {
					parse_segwit("bc1")?;
				} else if k.eq_ignore_ascii_case("tb") || k.eq_ignore_ascii_case("req-tb") {
					parse_segwit("tb1")?;
				} else if k.eq_ignore_ascii_case("lightning")
					|| k.eq_ignore_ascii_case("req-lightning")
				{
					if let Some(invoice_string) = v {
						let invoice = Bolt11Invoice::from_str(invoice_string)
							.map_err(ParseError::InvalidBolt11)?;
						let (desc, amounts, method_iter) =
							instructions_from_bolt11(invoice, network)?;
						if let Some(fallbacks_amt) = amounts.fallbacks_amount {
							if onchain_amt.is_some() && onchain_amt != Some(fallbacks_amt) {
								let err = "BIP 321 bitcoin: URI contains lightning (BOLT 11 invoice) instructions with varying values";
								return Err(ParseError::InconsistentInstructions(err));
							}
							onchain_amt = Some(fallbacks_amt);
						}
						if let Some(desc) = desc {
							description = Some(desc);
						}
						for method in method_iter {
							methods.push(method);
						}
					} else {
						let err = "BIP 321 bitcoin: URI contained a lightning (BOLT 11 invoice) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("creq") || k.eq_ignore_ascii_case("req-creq") {
					if let Some(creq_string) = v {
						let creq = cashu::CashuPaymentRequest::from_str(creq_string)
							.map_err(ParseError::InvalidCashu)?;
						if let Some(desc) = &creq.description {
							description = Some(desc.clone());
						}
						methods.push(PaymentMethod::Cashu(creq));
					} else {
						let err = "BIP 321 bitcoin: URI contained a creq (Cashu) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("lno") || k.eq_ignore_ascii_case("req-lno") {
					if let Some(offer_string) = v {
						let offer =
							Offer::from_str(offer_string).map_err(ParseError::InvalidBolt12)?;
						let (desc, method) = check_offer(offer, network)?;
						if let Some(desc) = desc {
							description = Some(desc);
						}
						methods.push(method);
					} else {
						let err = "BIP 321 bitcoin: URI contained a lightning (BOLT 11 invoice) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("amount") || k.eq_ignore_ascii_case("req-amount") {
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("label") || k.eq_ignore_ascii_case("req-label") {
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("message") || k.eq_ignore_ascii_case("req-message")
				{
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("pop") || k.eq_ignore_ascii_case("req-pop") {
					if k.eq_ignore_ascii_case("req-pop") && !supports_proof_of_payment_callbacks {
						return Err(ParseError::UnknownRequiredParameter);
					}
					if pop_callback.is_some() {
						let err = "Multiple proof of payment callbacks appeared in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					if let Some(v) = v {
						let callback_uri = un_percent_encode(v)?;
						let (proto, _) = split_once(&callback_uri, ':');
						let proto_isnt_local_app = proto.eq_ignore_ascii_case("javascript")
							|| proto.eq_ignore_ascii_case("http")
							|| proto.eq_ignore_ascii_case("https")
							|| proto.eq_ignore_ascii_case("file")
							|| proto.eq_ignore_ascii_case("mailto")
							|| proto.eq_ignore_ascii_case("ftp")
							|| proto.eq_ignore_ascii_case("wss")
							|| proto.eq_ignore_ascii_case("ws")
							|| proto.eq_ignore_ascii_case("ssh")
							|| proto.eq_ignore_ascii_case("tel") // lol
							|| proto.eq_ignore_ascii_case("data")
							|| proto.eq_ignore_ascii_case("blob");
						if proto_isnt_local_app {
							let err = "Proof of payment callback would not have opened a local app";
							return Err(ParseError::InvalidInstructions(err));
						}
						pop_callback = Some(callback_uri);
					} else {
						let err = "Missing value for a Proof of Payment instruction in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.is_char_boundary(4) && k[..4].eq_ignore_ascii_case("req-") {
					return Err(ParseError::UnknownRequiredParameter);
				}
			}
			let mut label = None;
			let mut message = None;
			let mut had_amt_param = false;
			for param in params.split('&') {
				let (k, v) = split_once(param, '=');
				if k.eq_ignore_ascii_case("amount") || k.eq_ignore_ascii_case("req-amount") {
					if let Some(v) = v {
						if had_amt_param {
							let err = "Multiple amount parameters in a BIP 321 bitcoin: URI ";
							return Err(ParseError::InvalidInstructions(err));
						}
						had_amt_param = true;

						let err = "The amount parameter in a BIP 321 bitcoin: URI was invalid";
						let btc_amt =
							bitcoin::Amount::from_str_in(v, bitcoin::Denomination::Bitcoin)
								.map_err(|_| ParseError::InvalidInstructions(err))?;

						let err = "The amount parameter in a BIP 321 bitcoin: URI was greater than 21M BTC";
						let amount = Amount::from_sats(btc_amt.to_sat())
							.map_err(|_| ParseError::InvalidInstructions(err))?;

						if onchain_amt.is_some() && onchain_amt != Some(amount) {
							let err = "On-chain fallbacks from a lightning BOLT 11 invoice and the amount parameter in a BIP 321 bitcoin: URI differed in their amounts";
							return Err(ParseError::InconsistentInstructions(err));
						}
						onchain_amt = Some(amount);
					} else {
						let err = "Missing value for an amount parameter in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("label") || k.eq_ignore_ascii_case("req-label") {
					if label.is_some() {
						let err = "Multiple label parameters in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					label = v;
				} else if k.eq_ignore_ascii_case("message") || k.eq_ignore_ascii_case("req-message")
				{
					if message.is_some() {
						let err = "Multiple message parameters in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					message = v;
				}
			}

			if methods.is_empty() {
				return Err(ParseError::UnknownPaymentInstructions);
			}

			let mut min_amt = Amount::MAX;
			let mut max_amt = Amount::ZERO;
			let mut ln_amt = None;
			let mut cashu_amt = None;
			let mut have_amountless_method = false;
			let mut have_non_btc_denominated_method = false;
			for method in methods.iter() {
				let amt = match method {
					PaymentMethod::LightningBolt11(_)
					| PaymentMethod::LightningBolt12(_)
					| PaymentMethod::Cashu(_) => method.amount(),
					PaymentMethod::OnChain(_) => onchain_amt,
				};
				if let Some(amt) = amt {
					if amt < min_amt {
						min_amt = amt;
					}
					if amt > max_amt {
						max_amt = amt;
					}
					match method {
						PaymentMethod::LightningBolt11(_) | PaymentMethod::LightningBolt12(_) => {
							if let Some(ln_amt) = ln_amt {
								if ln_amt != amt {
									let err = "Had multiple different amounts in lightning payment methods in a BIP 321 bitcoin: URI";
									return Err(ParseError::InconsistentInstructions(err));
								}
							}
							ln_amt = Some(amt);
						},
						PaymentMethod::Cashu(_) => {
							if let Some(c_amt) = cashu_amt {
								if c_amt != amt {
									let err = "Had multiple different amounts in Cashu payment methods in a BIP 321 bitcoin: URI";
									return Err(ParseError::InconsistentInstructions(err));
								}
							}
							cashu_amt = Some(amt);
						},
						PaymentMethod::OnChain(_) => {},
					}
				} else if method.has_fixed_amount() {
					have_non_btc_denominated_method = true;
				} else {
					have_amountless_method = true;
				}
			}
			if have_amountless_method && have_non_btc_denominated_method {
				let err = "Had some payment methods in a BIP 321 bitcoin: URI with required (non-BTC-denominated) amounts, some without";
				return Err(ParseError::InconsistentInstructions(err));
			}
			let cant_have_amt = have_amountless_method || have_non_btc_denominated_method;
			if (min_amt != Amount::MAX || max_amt != Amount::ZERO) && cant_have_amt {
				let err = "Had some payment methods in a BIP 321 bitcoin: URI with required amounts, some without";
				return Err(ParseError::InconsistentInstructions(err));
			}
			if max_amt.saturating_sub(min_amt) > MAX_AMOUNT_DIFFERENCE {
				let err = "Payment methods differed in ";
				return Err(ParseError::InconsistentInstructions(err));
			}

			let inner = PaymentInstructionsImpl {
				description,
				methods,
				onchain_amt,
				ln_amt,
				cashu_amt,
				lnurl: None,
				pop_callback,
				hrn,
				hrn_proof,
			};
			if !have_amountless_method || have_non_btc_denominated_method {
				Ok(PaymentInstructions::FixedAmount(FixedAmountPaymentInstructions { inner }))
			} else {
				Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
					inner,
				}))
			}
		} else {
			// No parameters were provided, so we just have the on-chain address in the URI body.
			if methods.is_empty() {
				Err(ParseError::UnknownPaymentInstructions)
			} else {
				let inner = PaymentInstructionsImpl {
					description,
					methods,
					onchain_amt: None,
					ln_amt: None,
					cashu_amt: None,
					lnurl: None,
					pop_callback,
					hrn,
					hrn_proof,
				};
				Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
					inner,
				}))
			}
		}
	} else if uri_proto.eq_ignore_ascii_case("lightning") {
		// Though there is no specification, lightning: URIs generally only include BOLT 11
		// invoices.
		let invoice =
			Bolt11Invoice::from_str(uri_suffix.unwrap_or("")).map_err(ParseError::InvalidBolt11)?;
		let (description, amounts, method_iter) = instructions_from_bolt11(invoice, network)?;
		let inner = PaymentInstructionsImpl {
			description,
			methods: method_iter.collect(),
			onchain_amt: amounts.fallbacks_amount,
			ln_amt: amounts.ln_amount,
			cashu_amt: None,
			lnurl: None,
			pop_callback: None,
			hrn,
			hrn_proof,
		};
		if amounts.ln_amount.is_some() {
			Ok(PaymentInstructions::FixedAmount(FixedAmountPaymentInstructions { inner }))
		} else {
			Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
				inner,
			}))
		}
	} else if let Ok(addr) = Address::from_str(instructions) {
		let address = addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
		Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
			inner: PaymentInstructionsImpl {
				description: None,
				methods: vec![PaymentMethod::OnChain(address)],
				onchain_amt: None,
				ln_amt: None,
				cashu_amt: None,
				lnurl: None,
				pop_callback: None,
				hrn,
				hrn_proof,
			},
		}))
	} else if let Ok(invoice) = Bolt11Invoice::from_str(instructions) {
		let (description, amounts, method_iter) = instructions_from_bolt11(invoice, network)?;
		let inner = PaymentInstructionsImpl {
			description,
			methods: method_iter.collect(),
			onchain_amt: amounts.fallbacks_amount,
			ln_amt: amounts.ln_amount,
			cashu_amt: None,
			lnurl: None,
			pop_callback: None,
			hrn,
			hrn_proof,
		};
		if amounts.ln_amount.is_some() {
			Ok(PaymentInstructions::FixedAmount(FixedAmountPaymentInstructions { inner }))
		} else {
			Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
				inner,
			}))
		}
	} else if let Ok(creq) = cashu::CashuPaymentRequest::from_str(instructions) {
		let has_amt = creq.amount.is_some()
			&& (creq.unit == Some(cashu::CurrencyUnit::Sat)
				|| creq.unit == Some(cashu::CurrencyUnit::Msat));
		let description = creq.description.clone();
		let cashu_amt = if has_amt {
			match creq.unit {
				Some(cashu::CurrencyUnit::Sat) => {
					creq.amount.and_then(|a| Amount::from_sats(a).ok())
				},
				Some(cashu::CurrencyUnit::Msat) => {
					creq.amount.and_then(|a| Amount::from_milli_sats(a).ok())
				},
				_ => None,
			}
		} else {
			None
		};
		let inner = PaymentInstructionsImpl {
			description,
			methods: vec![PaymentMethod::Cashu(creq)],
			onchain_amt: None,
			ln_amt: None, // This will be filled by PaymentInstructions accessors if unit is sat/msat
			cashu_amt,
			lnurl: None,
			pop_callback: None,
			hrn,
			hrn_proof,
		};
		if has_amt {
			Ok(PaymentInstructions::FixedAmount(FixedAmountPaymentInstructions { inner }))
		} else {
			Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
				inner,
			}))
		}
	} else if let Ok(offer) = Offer::from_str(instructions) {
		let has_amt = offer.amount().is_some();
		let (description, method) = check_offer(offer, network)?;
		let inner = PaymentInstructionsImpl {
			ln_amt: method.amount(),
			description,
			methods: vec![method],
			onchain_amt: None,
			cashu_amt: None,
			lnurl: None,
			pop_callback: None,
			hrn,
			hrn_proof,
		};
		if has_amt {
			Ok(PaymentInstructions::FixedAmount(FixedAmountPaymentInstructions { inner }))
		} else {
			Ok(PaymentInstructions::ConfigurableAmount(ConfigurableAmountPaymentInstructions {
				inner,
			}))
		}
	} else {
		Err(ParseError::UnknownPaymentInstructions)
	}
}

impl PaymentInstructions {
	/// Resolves a string into [`PaymentInstructions`].
	pub async fn parse<H: HrnResolver>(
		instructions: &str, network: Network, hrn_resolver: &H,
		supports_proof_of_payment_callbacks: bool,
	) -> Result<PaymentInstructions, ParseError> {
		let supports_pops = supports_proof_of_payment_callbacks;
		let (uri_proto, _uri_suffix) = split_once(instructions, ':');

		if let Ok(hrn) = HumanReadableName::from_encoded(instructions) {
			let resolution = hrn_resolver.resolve_hrn(&hrn).await;
			let resolution = resolution.map_err(ParseError::HrnResolutionError)?;
			match resolution {
				HrnResolution::DNSSEC { proof, result } => {
					parse_resolved_instructions(&result, network, supports_pops, Some(hrn), proof)
				},
				HrnResolution::LNURLPay {
					min_value,
					max_value,
					expected_description_hash,
					recipient_description,
					callback,
				} => {
					let inner = PaymentInstructionsImpl {
						description: recipient_description,
						methods: Vec::new(),
						lnurl: Some((callback, expected_description_hash, min_value, max_value)),
						onchain_amt: None,
						ln_amt: None,
						cashu_amt: None,
						pop_callback: None,
						hrn: Some(hrn),
						hrn_proof: None,
					};
					Ok(PaymentInstructions::ConfigurableAmount(
						ConfigurableAmountPaymentInstructions { inner },
					))
				},
			}
		} else if uri_proto.eq_ignore_ascii_case("bitcoin:") {
			// If it looks like a BIP 353 URI, jump straight to parsing it and ignore any LNURL
			// overrides.
			parse_resolved_instructions(instructions, network, supports_pops, None, None)
		} else if let Some(idx) = instructions.to_ascii_lowercase().rfind("lnurl") {
			let mut lnurl_str = &instructions[idx..];
			// first try to decode as a bech32-encoded lnurl, if that fails, try to drop a
			// trailing `&` and decode again, this could a http query param
			if let Some(idx) = lnurl_str.find('&') {
				lnurl_str = &lnurl_str[..idx];
			}
			if let Some(idx) = lnurl_str.find('#') {
				lnurl_str = &lnurl_str[..idx];
			}
			if let Ok((_, data)) = bitcoin::bech32::decode(lnurl_str) {
				let url = String::from_utf8(data)
					.map_err(|_| ParseError::InvalidLnurl("Not utf-8 encoded string"))?;
				let resolution = hrn_resolver.resolve_lnurl(&url).await;
				let resolution = resolution.map_err(ParseError::HrnResolutionError)?;
				match resolution {
					HrnResolution::DNSSEC { .. } => Err(ParseError::HrnResolutionError(
						"Unexpected return when resolving lnurl",
					)),
					HrnResolution::LNURLPay {
						min_value,
						max_value,
						expected_description_hash,
						recipient_description,
						callback,
					} => {
						let inner = PaymentInstructionsImpl {
							description: recipient_description,
							methods: Vec::new(),
							lnurl: Some((
								callback,
								expected_description_hash,
								min_value,
								max_value,
							)),
							onchain_amt: None,
							ln_amt: None,
							cashu_amt: None,
							pop_callback: None,
							hrn: None,
							hrn_proof: None,
						};
						Ok(PaymentInstructions::ConfigurableAmount(
							ConfigurableAmountPaymentInstructions { inner },
						))
					},
				}
			} else {
				parse_resolved_instructions(instructions, network, supports_pops, None, None)
			}
		} else {
			parse_resolved_instructions(instructions, network, supports_pops, None, None)
		}
	}
}

#[cfg(test)]
mod tests {
	use alloc::format;
	use alloc::str::FromStr;
	#[cfg(not(feature = "std"))]
	use alloc::string::ToString;

	use super::*;

	use crate::hrn_resolution::DummyHrnResolver;

	const SAMPLE_INVOICE_WITH_FALLBACK: &str = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0";
	const SAMPLE_INVOICE: &str = "lnbc20m1pn7qa2ndqqnp4q0d3p2sfluzdx45tqcsh2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5kwzshmne5zw3lnfqdk8cv26mg9ndjapqzhcxn2wtn9d6ew5e2jfqsp5h3u5f0l522vs488h6n8zm5ca2lkpva532fnl2kp4wnvsuq445erq9qyysgqcqpcxqppz4395v2sjh3t5pzckgeelk9qf0z3fm9jzxtjqpqygayt4xyy7tpjvq5pe7f6727du2mg3t2tfe0cd53de2027ff7es7smtew8xx5x2spwuvkdz";
	const SAMPLE_OFFER: &str = "lno1qgs0v8hw8d368q9yw7sx8tejk2aujlyll8cp7tzzyh5h8xyppqqqqqqgqvqcdgq2qenxzatrv46pvggrv64u366d5c0rr2xjc3fq6vw2hh6ce3f9p7z4v4ee0u7avfynjw9q";
	const SAMPLE_BIP21: &str = "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz";

	#[cfg(feature = "http")]
	const SAMPLE_LNURL: &str = "LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK";
	#[cfg(feature = "http")]
	const SAMPLE_LNURL_LN_PREFIX: &str = "lightning:LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK";
	#[cfg(feature = "http")]
	const SAMPLE_LNURL_FALLBACK: &str = "https://service.com/giftcard/redeem?id=123&lightning=LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK";
	#[cfg(feature = "http")]
	const SAMPLE_LNURL_FALLBACK_WITH_AND: &str = "https://service.com/giftcard/redeem?id=123&lightning=LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK&extra=my_extra_param";
	#[cfg(feature = "http")]
	const SAMPLE_LNURL_FALLBACK_WITH_HASHTAG: &str = "https://service.com/giftcard/redeem?id=123&lightning=LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK#extra=my_extra_param";
	#[cfg(feature = "http")]
	const SAMPLE_LNURL_FALLBACK_WITH_BOTH: &str = "https://service.com/giftcard/redeem?id=123&lightning=LNURL1DP68GURN8GHJ7MRWW4EXCTNDW46XJMNEDEJHGTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHHYETXW4HXG0AH8NK&extra=my_extra_param#extra2=another_extra_param";

	const SAMPLE_BIP21_WITH_INVOICE: &str = "bitcoin:BC1QYLH3U67J673H6Y6ALV70M0PL2YZ53TZHVXGG7U?amount=0.00001&label=sbddesign%3A%20For%20lunch%20Tuesday&message=For%20lunch%20Tuesday&lightning=LNBC10U1P3PJ257PP5YZTKWJCZ5FTL5LAXKAV23ZMZEKAW37ZK6KMV80PK4XAEV5QHTZ7QDPDWD3XGER9WD5KWM36YPRX7U3QD36KUCMGYP282ETNV3SHJCQZPGXQYZ5VQSP5USYC4LK9CHSFP53KVCNVQ456GANH60D89REYKDNGSMTJ6YW3NHVQ9QYYSSQJCEWM5CJWZ4A6RFJX77C490YCED6PEMK0UPKXHY89CMM7SCT66K8GNEANWYKZGDRWRFJE69H9U5U0W57RRCSYSAS7GADWMZXC8C6T0SPJAZUP6";
	#[cfg(not(feature = "std"))]
	const SAMPLE_BIP21_WITH_INVOICE_ADDR: &str = "bc1qylh3u67j673h6y6alv70m0pl2yz53tzhvxgg7u";
	#[cfg(not(feature = "std"))]
	const SAMPLE_BIP21_WITH_INVOICE_INVOICE: &str = "lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpdwd3xger9wd5kwm36yprx7u3qd36kucmgyp282etnv3shjcqzpgxqyz5vqsp5usyc4lk9chsfp53kvcnvq456ganh60d89reykdngsmtj6yw3nhvq9qyyssqjcewm5cjwz4a6rfjx77c490yced6pemk0upkxhy89cmm7sct66k8gneanwykzgdrwrfje69h9u5u0w57rrcsysas7gadwmzxc8c6t0spjazup6";

	const SAMPLE_BIP21_WITH_INVOICE_AND_LABEL: &str = "bitcoin:tb1p0vztr8q25czuka5u4ta5pqu0h8dxkf72mam89cpg4tg40fm8wgmqp3gv99?amount=0.000001&label=yooo&lightning=lntbs1u1pjrww6fdq809hk7mcnp4qvwggxr0fsueyrcer4x075walsv93vqvn3vlg9etesx287x6ddy4xpp5a3drwdx2fmkkgmuenpvmynnl7uf09jmgvtlg86ckkvgn99ajqgtssp5gr3aghgjxlwshnqwqn39c2cz5hw4cnsnzxdjn7kywl40rru4mjdq9qyysgqcqpcxqrpwurzjqfgtsj42x8an5zujpxvfhp9ngwm7u5lu8lvzfucjhex4pq8ysj5q2qqqqyqqv9cqqsqqqqlgqqqqqqqqfqzgl9zq04nzpxyvdr8vj3h98gvnj3luanj2cxcra0q2th4xjsxmtj8k3582l67xq9ffz5586f3nm5ax58xaqjg6rjcj2vzvx2q39v9eqpn0wx54";

	#[tokio::test]
	async fn parse_cashu() {
		let creq = "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQVXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YPCXZ7TDV4H8GXHR3TQ";
		let parsed = PaymentInstructions::parse(creq, Network::Bitcoin, &DummyHrnResolver, false)
			.await
			.unwrap();

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!("Expected FixedAmount for Cashu with amount"),
		};

		assert_eq!(parsed.methods().len(), 1);
		assert_eq!(parsed.cashu_payment_amount(), Some(Amount::from_sats(1000).unwrap()));
		// Max amount should pick up the cashu amount
		assert_eq!(parsed.max_amount(), Some(Amount::from_sats(1000).unwrap()));
		assert_eq!(parsed.recipient_description(), Some("Coffee payment"));

		if let PaymentMethod::Cashu(req) = &parsed.methods()[0] {
			assert_eq!(req.amount, Some(1000));
			assert_eq!(req.unit, Some(cashu::CurrencyUnit::Sat));
		} else {
			panic!("Wrong method type");
		}
	}

	#[tokio::test]
	async fn parse_bip_21_with_creq() {
		let creq = "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQVXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YPCXZ7TDV4H8GXHR3TQ";
		let uri = format!("bitcoin:?creq={}", creq);

		let parsed = PaymentInstructions::parse(&uri, Network::Bitcoin, &DummyHrnResolver, false)
			.await
			.unwrap();

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!("Expected FixedAmount"),
		};

		assert_eq!(parsed.methods().len(), 1);
		assert_eq!(parsed.max_amount(), Some(Amount::from_sats(1000).unwrap()));
		if let PaymentMethod::Cashu(_) = &parsed.methods()[0] {
			// ok
		} else {
			panic!("Wrong method");
		}
	}

	#[tokio::test]
	async fn parse_address() {
		let addr_str = "1andreas3batLhQa2FawWjeyjCqyBzypd";
		let parsed =
			PaymentInstructions::parse(&addr_str, Network::Bitcoin, &DummyHrnResolver, false)
				.await
				.unwrap();

		assert_eq!(parsed.recipient_description(), None);

		let resolved = match parsed {
			PaymentInstructions::ConfigurableAmount(parsed) => {
				assert_eq!(parsed.min_amt(), None);
				assert_eq!(parsed.min_amt(), None);
				assert_eq!(parsed.methods().collect::<Vec<_>>().len(), 1);
				parsed.set_amount(Amount::from_sats(10).unwrap(), &DummyHrnResolver).await.unwrap()
			},
			_ => panic!(),
		};

		assert_eq!(resolved.methods().len(), 1);
		if let PaymentMethod::OnChain(address) = &resolved.methods()[0] {
			assert_eq!(*address, Address::from_str(addr_str).unwrap().assume_checked());
		} else {
			panic!("Wrong method");
		}
	}

	// Test a handful of ways a lightning invoice might be communicated
	async fn check_ln_invoice(inv: &str) -> Result<PaymentInstructions, ParseError> {
		assert!(inv.chars().all(|c| c.is_ascii_lowercase() || c.is_digit(10)), "{}", inv);
		let resolver = &DummyHrnResolver;
		let raw = PaymentInstructions::parse(inv, Network::Bitcoin, resolver, false).await;

		let ln_uri = format!("lightning:{}", inv);
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let ln_uri = format!("LIGHTNING:{}", inv);
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let ln_uri = ln_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?lightning={}", inv);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?req-lightning={}", inv);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		raw
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_invoice() {
		let invoice = Bolt11Invoice::from_str(SAMPLE_INVOICE).unwrap();
		let parsed = check_ln_invoice(SAMPLE_INVOICE).await.unwrap();

		let amt = invoice.amount_milli_satoshis().map(Amount::from_milli_sats).unwrap().unwrap();

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		assert_eq!(parsed.methods().len(), 1);
		assert_eq!(parsed.ln_payment_amount().unwrap(), amt);
		assert_eq!(parsed.onchain_payment_amount(), None);
		assert_eq!(parsed.max_amount().unwrap(), amt);
		assert_eq!(parsed.recipient_description(), Some(""));
		assert!(matches!(&parsed.methods()[0], &PaymentMethod::LightningBolt11(_)));
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_invoice() {
		assert_eq!(check_ln_invoice(SAMPLE_INVOICE).await, Err(ParseError::InstructionsExpired));
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_invoice_with_fallback() {
		let invoice = Bolt11Invoice::from_str(SAMPLE_INVOICE_WITH_FALLBACK).unwrap();
		let parsed = check_ln_invoice(SAMPLE_INVOICE_WITH_FALLBACK).await.unwrap();

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		assert_eq!(parsed.methods().len(), 2);
		assert_eq!(
			parsed.max_amount().unwrap(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats).unwrap().unwrap(),
		);
		assert_eq!(
			parsed.ln_payment_amount().unwrap(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats).unwrap().unwrap(),
		);
		assert_eq!(
			parsed.onchain_payment_amount().unwrap(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats).unwrap().unwrap(),
		);

		assert_eq!(parsed.recipient_description(), None); // no description for a description hash
		let is_bolt11 = |meth: &&PaymentMethod| matches!(meth, &&PaymentMethod::LightningBolt11(_));
		assert_eq!(parsed.methods().iter().filter(is_bolt11).count(), 1);
		let is_onchain = |meth: &&PaymentMethod| matches!(meth, &&PaymentMethod::OnChain { .. });
		assert_eq!(parsed.methods().iter().filter(is_onchain).count(), 1);
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_invoice_with_fallback() {
		assert_eq!(
			check_ln_invoice(SAMPLE_INVOICE_WITH_FALLBACK).await,
			Err(ParseError::InstructionsExpired),
		);
	}

	// Test a handful of ways a lightning offer might be communicated
	async fn check_ln_offer(offer: &str) -> Result<PaymentInstructions, ParseError> {
		assert!(offer.chars().all(|c| c.is_ascii_lowercase() || c.is_digit(10)), "{}", offer);
		let resolver = &DummyHrnResolver;
		let raw = PaymentInstructions::parse(offer, Network::Signet, resolver, false).await;

		let btc_uri = format!("bitcoin:?lno={}", offer);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?req-lno={}", offer);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		raw
	}

	#[tokio::test]
	async fn parse_offer() {
		let offer = Offer::from_str(SAMPLE_OFFER).unwrap();
		let amt_msats = match offer.amount() {
			None => None,
			Some(offer::Amount::Bitcoin { amount_msats }) => Some(amount_msats),
			Some(offer::Amount::Currency { .. }) => panic!(),
		};
		let parsed = check_ln_offer(SAMPLE_OFFER).await.unwrap();

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		assert_eq!(parsed.methods().len(), 1);
		assert_eq!(
			parsed.methods()[0].amount().unwrap(),
			amt_msats.map(Amount::from_milli_sats).unwrap().unwrap()
		);
		assert_eq!(parsed.recipient_description(), Some("faucet"));
		assert!(matches!(parsed.methods()[0], PaymentMethod::LightningBolt12(_)));
	}

	#[tokio::test]
	async fn parse_bip_21() {
		let parsed =
			PaymentInstructions::parse(SAMPLE_BIP21, Network::Bitcoin, &DummyHrnResolver, false)
				.await
				.unwrap();

		assert_eq!(parsed.recipient_description(), None);

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		let expected_amount = Amount::from_sats(5_000_000_000).unwrap();

		assert_eq!(parsed.methods().len(), 1);
		assert_eq!(parsed.max_amount(), Some(expected_amount));
		assert_eq!(parsed.ln_payment_amount(), None);
		assert_eq!(parsed.onchain_payment_amount(), Some(expected_amount));
		assert_eq!(parsed.recipient_description(), None);
		assert!(matches!(parsed.methods()[0], PaymentMethod::OnChain(_)));
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_bip_21_with_invoice() {
		let parsed = PaymentInstructions::parse(
			SAMPLE_BIP21_WITH_INVOICE,
			Network::Bitcoin,
			&DummyHrnResolver,
			false,
		)
		.await
		.unwrap();

		assert_eq!(parsed.recipient_description(), Some("sbddesign: For lunch Tuesday"));

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		let expected_amount = Amount::from_milli_sats(1_000_000).unwrap();

		assert_eq!(parsed.methods().len(), 2);
		assert_eq!(parsed.onchain_payment_amount(), Some(expected_amount));
		assert_eq!(parsed.ln_payment_amount(), Some(expected_amount));
		assert_eq!(parsed.max_amount(), Some(expected_amount));
		assert_eq!(parsed.recipient_description(), Some("sbddesign: For lunch Tuesday"));
		if let PaymentMethod::OnChain(address) = &parsed.methods()[0] {
			assert_eq!(address.to_string(), SAMPLE_BIP21_WITH_INVOICE_ADDR);
		} else {
			panic!("Missing on-chain (or order changed)");
		}
		if let PaymentMethod::LightningBolt11(inv) = &parsed.methods()[1] {
			assert_eq!(inv.to_string(), SAMPLE_BIP21_WITH_INVOICE_INVOICE);
		} else {
			panic!("Missing invoice (or order changed)");
		}
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_bip_21_with_invoice() {
		assert_eq!(
			PaymentInstructions::parse(
				SAMPLE_BIP21_WITH_INVOICE,
				Network::Bitcoin,
				&DummyHrnResolver,
				false,
			)
			.await,
			Err(ParseError::InstructionsExpired),
		);
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_bip_21_with_invoice_with_label() {
		let parsed = PaymentInstructions::parse(
			SAMPLE_BIP21_WITH_INVOICE_AND_LABEL,
			Network::Signet,
			&DummyHrnResolver,
			false,
		)
		.await
		.unwrap();

		assert_eq!(parsed.recipient_description(), Some("yooo"));

		let parsed = match parsed {
			PaymentInstructions::FixedAmount(parsed) => parsed,
			_ => panic!(),
		};

		let expected_amount = Amount::from_milli_sats(100_000).unwrap();

		assert_eq!(parsed.methods().len(), 2);
		assert_eq!(parsed.max_amount(), Some(expected_amount));
		assert_eq!(parsed.onchain_payment_amount(), Some(expected_amount));
		assert_eq!(parsed.ln_payment_amount(), Some(expected_amount));
		assert_eq!(parsed.recipient_description(), Some("yooo"));
		assert!(matches!(parsed.methods()[0], PaymentMethod::OnChain(_)));
		assert!(matches!(parsed.methods()[1], PaymentMethod::LightningBolt11(_)));
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_bip_21_with_invoice_with_label() {
		assert_eq!(
			PaymentInstructions::parse(
				SAMPLE_BIP21_WITH_INVOICE_AND_LABEL,
				Network::Signet,
				&DummyHrnResolver,
				false,
			)
			.await,
			Err(ParseError::InstructionsExpired),
		);
	}

	#[cfg(feature = "http")]
	async fn test_lnurl(str: &str) {
		let resolver = http_resolver::HTTPHrnResolver::default();
		let parsed =
			PaymentInstructions::parse(str, Network::Signet, &resolver, false).await.unwrap();

		let parsed = match parsed {
			PaymentInstructions::ConfigurableAmount(parsed) => parsed,
			_ => panic!(),
		};

		assert_eq!(parsed.methods().count(), 1);
		assert_eq!(parsed.min_amt(), Some(Amount::from_milli_sats(1000).unwrap()));
		assert_eq!(parsed.max_amt(), Some(Amount::from_milli_sats(11000000000).unwrap()));
	}

	#[cfg(feature = "http")]
	#[tokio::test]
	async fn parse_lnurl() {
		test_lnurl(SAMPLE_LNURL).await;
		test_lnurl(SAMPLE_LNURL_LN_PREFIX).await;
		test_lnurl(SAMPLE_LNURL_FALLBACK).await;
		test_lnurl(SAMPLE_LNURL_FALLBACK_WITH_AND).await;
		test_lnurl(SAMPLE_LNURL_FALLBACK_WITH_HASHTAG).await;
		test_lnurl(SAMPLE_LNURL_FALLBACK_WITH_BOTH).await;
	}
}
