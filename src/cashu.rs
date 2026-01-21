//! NUT-26: Bech32m encoding for payment requests
//!
//! This module provides bech32m encoding and decoding functionality for Cashu payment requests,
//! implementing the CREQ-B format using TLV (Tag-Length-Value) encoding as specified in NUT-26.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::str::FromStr;

use bitcoin::bech32::{self, Bech32m, Hrp};

/// Human-readable part for CREQ-B bech32m encoding
pub const CREQ_B_HRP: &str = "creqb";

/// Maximum number of bytes that can be stored inline in a `UnitString`.
/// Set to 11 so that `UnitString` fits in 12 bytes (matching `String` on 32-bit systems).
const INLINE_UNIT_BYTES: usize = 11;

/// Errors that can occur during parsing and encoding of Cashu payment requests
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Invalid HRP prefix (must be `creqb`)
	InvalidPrefix,
	/// Invalid length of a TLV field or the overall structure
	InvalidLength,
	/// Invalid UTF-8 encoding in a string field
	InvalidUtf8,
	/// Unknown NUT-10 spending condition kind
	UnknownKind(u8),
	/// Bech32 encoding/decoding error
	Bech32,
	/// Invalid TLV structure (missing required fields, unexpected values, malformed TLV)
	InvalidStructure,
}

/// A string type optimized for short currency unit names.
///
/// Stores strings of 11 bytes or less inline without heap allocation.
/// Longer strings fall back to heap allocation.
#[derive(Clone, PartialEq, Eq)]
pub struct UnitString(UnitStringInner);

#[derive(Clone, PartialEq, Eq)]
enum UnitStringInner {
	Inline { bytes: [u8; INLINE_UNIT_BYTES], len: u8 },
	Heap(String),
}

impl UnitString {
	/// Creates a new `UnitString` from a string slice.
	pub fn new(s: &str) -> Self {
		let bytes = s.as_bytes();
		if bytes.len() <= INLINE_UNIT_BYTES {
			let mut arr = [0u8; INLINE_UNIT_BYTES];
			arr[..bytes.len()].copy_from_slice(bytes);
			Self(UnitStringInner::Inline { bytes: arr, len: bytes.len() as u8 })
		} else {
			Self(UnitStringInner::Heap(s.to_string()))
		}
	}

	/// Creates a `UnitString` from a byte slice, returning `None` if the bytes are not valid UTF-8.
	pub fn from_utf8(bytes: &[u8]) -> Option<Self> {
		core::str::from_utf8(bytes).ok().map(Self::new)
	}

	/// Returns the string as a string slice.
	pub fn as_str(&self) -> &str {
		match &self.0 {
			UnitStringInner::Inline { bytes, len } => {
				// We only store valid UTF-8 in the inline buffer via the
				// public constructors, and UnitStringInner is private.
				core::str::from_utf8(&bytes[..*len as usize])
					.expect("UnitString contains valid UTF-8")
			},
			UnitStringInner::Heap(s) => s.as_str(),
		}
	}

	/// Returns the string as a byte slice.
	pub fn as_bytes(&self) -> &[u8] {
		self.as_str().as_bytes()
	}
}

impl Deref for UnitString {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		self.as_str()
	}
}

impl AsRef<str> for UnitString {
	fn as_ref(&self) -> &str {
		self.as_str()
	}
}

impl fmt::Display for UnitString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl fmt::Debug for UnitString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl PartialEq<str> for UnitString {
	fn eq(&self, other: &str) -> bool {
		self.as_str() == other
	}
}

impl PartialEq<&str> for UnitString {
	fn eq(&self, other: &&str) -> bool {
		self.as_str() == *other
	}
}

impl From<&str> for UnitString {
	fn from(s: &str) -> Self {
		Self::new(s)
	}
}

impl From<String> for UnitString {
	fn from(s: String) -> Self {
		if s.len() <= INLINE_UNIT_BYTES {
			Self::new(&s)
		} else {
			Self(UnitStringInner::Heap(s))
		}
	}
}

/// Supported Currency Units
///
/// A mint may support any currency unit(s) they can mint and melt, either directly or indirectly.
/// Defined in [NUT-01](https://github.com/cashubtc/nuts/blob/main/01.md#supported-currency-units).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrencyUnit {
	/// Bitcoin's Minor Unit (satoshis).
	Sat,
	/// Millisatoshis.
	Msat,
	/// US Dollars (ISO 4217 code `usd`).
	/// Amounts represent cents (0.01 USD).
	Usd,
	/// Euro (ISO 4217 code `eur`).
	/// Amounts represent cents (0.01 EUR).
	Eur,
	/// Reserved for Blind Authentication.
	///
	/// These are special tokens (BATs) used to access protected mint endpoints while maintaining privacy.
	/// They function similarly to regular ecash but with a fixed amount of 1 and the unit `auth`.
	///
	/// In a payment request, this can be used to request access rights to a mint.
	/// The sender authenticates with the mint, gets BATs, and transfers them to the receiver,
	/// allowing the receiver to perform actions (like minting) on that mint without their own credentials.
	///
	/// See [NUT-22](https://github.com/cashubtc/nuts/blob/main/22.md).
	Auth,
	/// Custom unit (e.g., other ISO 4217 codes like `gbp`, `jpy`).
	/// Note: There is no length limit for the unit string according to the spec.
	Custom(UnitString),
}

impl CurrencyUnit {
	/// Creates a custom currency unit from a string slice.
	pub fn custom(s: &str) -> Self {
		Self::Custom(UnitString::new(s))
	}
}

/// The mechanism used to deliver the ecash token
///
/// Note: If the transport list is empty, it is implicitly assumed that the payment
/// will be delivered in-band (e.g., in an HTTP response header as in
/// [X-Cashu/NUT-24](https://github.com/cashubtc/nuts/blob/main/24.md)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
	/// Send via Nostr Direct Message (NIP-17)
	Nostr,
	/// Send via HTTP POST request
	HttpPost,
}

/// A value in a TagTuple, stored inline to avoid heap allocation.
/// Maximum length is 255 bytes (enforced by the TLV encoding).
#[derive(Copy, Clone, Eq)]
pub struct TagValue {
	bytes: [u8; 255],
	len: u8,
}

impl TagValue {
	/// Create a new TagValue from a string slice.
	pub fn new(s: &str) -> Result<Self, Error> {
		let bytes = s.as_bytes();
		if bytes.len() > u8::MAX as usize {
			return Err(Error::InvalidLength);
		}
		let mut arr = [0u8; 255];
		arr[..bytes.len()].copy_from_slice(bytes);
		Ok(Self { bytes: arr, len: bytes.len() as u8 })
	}

	/// Returns the string slice.
	pub fn as_str(&self) -> &str {
		// We only construct from valid str in new()
		core::str::from_utf8(&self.bytes[..self.len as usize])
			.expect("TagValue contains valid UTF-8")
	}

	/// Returns the byte slice.
	pub fn as_bytes(&self) -> &[u8] {
		self.as_str().as_bytes()
	}
}

impl Deref for TagValue {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		self.as_str()
	}
}

impl AsRef<str> for TagValue {
	fn as_ref(&self) -> &str {
		self.as_str()
	}
}

impl fmt::Display for TagValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl fmt::Debug for TagValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl PartialEq for TagValue {
	fn eq(&self, other: &Self) -> bool {
		self.as_str() == other.as_str()
	}
}

impl PartialEq<str> for TagValue {
	fn eq(&self, other: &str) -> bool {
		self.as_str() == other
	}
}

impl PartialEq<&str> for TagValue {
	fn eq(&self, other: &&str) -> bool {
		self.as_str() == *other
	}
}

impl PartialEq<String> for TagValue {
	fn eq(&self, other: &String) -> bool {
		self.as_str() == other.as_str()
	}
}

/// A tag tuple containing a key and zero or more values.
///
/// This represents the generic tag format used in NUT-18/NUT-26 for both
/// transport tags and NUT-10 spending condition tags.
/// In JSON, this is represented as `["key", "value1", "value2", ...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagTuple {
	/// The tag key (e.g., "n" for NIPs, "locktime" for timelocks)
	key: TagValue,
	/// The tag values
	values: Vec<TagValue>,
}

impl TagTuple {
	/// Create a new tag tuple with a key and values.
	///
	/// Returns an error if the key or any value exceeds 255 bytes.
	pub fn new<I, S>(key: &str, values: I) -> Result<Self, Error>
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let key = TagValue::new(key)?;
		let values_iter = values.into_iter();
		let mut tag_values = Vec::with_capacity(values_iter.size_hint().0);
		for value in values_iter {
			tag_values.push(TagValue::new(value.as_ref())?);
		}
		Ok(Self { key, values: tag_values })
	}

	/// Create a tag tuple with a single value.
	///
	/// Returns an error if the key or value exceeds 255 bytes.
	pub fn single(key: &str, value: &str) -> Result<Self, Error> {
		let key = TagValue::new(key)?;
		Ok(Self { key, values: vec![TagValue::new(value)?] })
	}

	/// Returns the tag key.
	pub fn key(&self) -> &str {
		&self.key
	}

	/// Returns the tag values.
	pub fn values(&self) -> &[TagValue] {
		&self.values
	}
}

/// Transport configuration for sending ecash
///
/// Defines how and where the wallet should send the proofs (ecash) to fulfill the payment request.
/// This allows the receiver to specify their preferred method of receiving the payment,
/// such as via a Nostr direct message or an HTTP POST request.
///
/// The transport can be empty. If the transport is empty, it is implicitly assumed that the payment will be in-band.
/// An example is [X-Cashu](https://github.com/cashubtc/nuts/blob/main/24.md) where the payment is expected in the HTTP header of a request.
/// We can only hope that the protocol being used has a well-defined transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
	/// The method of transport to use (e.g. Nostr, HTTP)
	pub kind: TransportType,
	/// The target destination (e.g. nostr profile string, HTTP URL)
	pub target: String,
	/// Additional parameters for the transport (e.g. relays, specific NIPs)
	///
	/// For Nostr transports (`kind=0`), generic tag tuples are used.
	/// - Key `"n"`: Specifies the NIPs the receiver supports (e.g., `TagTuple::single("n", "17")`).
	///
	/// Note that relays are *not* stored here (though are encoded as tags in the bech32 encoding).
	/// Instead, they are included in the nostr profile string in [`Self::target`].
	pub tags: Vec<TagTuple>,
}

impl Transport {
	/// If [`Self::kind`] is [`TransportType::Nostr`], this returns the relays which are encoded as
	/// a part of the [`Self::target`] (nostr profile string). Otherwise, returns
	/// Err([`Error::InvalidStructure`])
	pub fn nostr_relays(&self) -> Result<Vec<String>, Error> {
		if self.kind == TransportType::Nostr {
			Ok(CashuPaymentRequest::decode_nprofile(&self.target)?.1)
		} else {
			Err(Error::InvalidStructure)
		}
	}
}

/// NUT-10 Spending Condition Kind
///
/// Specifies the type of spending condition required for the token.
/// These correspond to the "kind" field in NUT-10 spending conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
	/// Pay to Public Key (P2PK)
	///
	/// Tokens are locked to a public key and require a valid signature to spend.
	/// Defined in [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md).
	P2PK,
	/// Hash Time Locked Contract (HTLC)
	///
	/// Tokens are locked with a hash and/or a timelock.
	/// Defined in [NUT-14](https://github.com/cashubtc/nuts/blob/main/14.md).
	HTLC,
}

/// NUT-10 Spending Condition
///
/// Represents a requested spending condition for the ecash token.
/// The payee can specify requirements for the token secret, such as locking it to a public key (P2PK) or a hash (HTLC).
/// Defined in [NUT-10](https://github.com/cashubtc/nuts/blob/main/10.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nut10SecretRequest {
	/// The type of spending condition (e.g., P2PK or HTLC).
	pub kind: Kind,
	/// The data required for the spending condition.
	///
	/// - For P2PK, this is the 33-byte public key (hex-encoded).
	/// - For HTLC, this is the 32-byte hash of the preimage (hex-encoded).
	pub data: String,
	/// Optional tags for additional conditions.
	///
	/// Common tags include:
	/// - `TagTuple::single("locktime", "<timestamp>")`: Unix timestamp for time locks.
	/// - `TagTuple::single("refund", "<pubkey>")`: Public key for refund spending condition.
	/// - `TagTuple::single("sig", "<signature>")`: Signature for P2PK authorization.
	pub tags: Vec<TagTuple>,
}

impl Nut10SecretRequest {
	/// Create a new NUT-10 secret request
	pub fn new(kind: Kind, data: &str, tags: Vec<TagTuple>) -> Self {
		Self { kind, data: data.to_string(), tags }
	}
}

/// Cashu Payment Request
///
/// A standardised format for payment requests that supply a sending wallet with all information necessary to complete the transaction.
/// Defined in [NUT-18](https://github.com/cashubtc/nuts/blob/main/18.md).
/// The bech32 encoding is defined in [NUT-26](https://github.com/cashubtc/nuts/blob/main/26.md).
/// Note: This crate currently only supports the bech32 encoding format (CREQ-B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashuPaymentRequest {
	/// Payment ID to be included in the payment payload.
	pub payment_id: Option<String>,
	/// The amount of the requested payment.
	pub amount: Option<u64>,
	/// The unit of the requested payment.
	/// MUST be set if `amount` is set.
	pub unit: Option<CurrencyUnit>,
	/// Whether the payment request is for single use.
	pub single_use: Option<bool>,
	/// A set of mints from which the payment is requested.
	pub mints: Option<Vec<String>>,
	/// A human readable description that the sending wallet will display after scanning the request.
	pub description: Option<String>,
	/// The method of `Transport` chosen to transmit the payment.
	/// Can be multiple, sorted by preference.
	pub transports: Vec<Transport>,
	/// The required NUT-10 spending conditions.
	pub nut10: Option<Nut10SecretRequest>,
}

/// TLV reader helper for parsing binary TLV data
struct TlvReader<'a> {
	data: &'a [u8],
	position: usize,
}

impl<'a> TlvReader<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self { data, position: 0 }
	}

	fn read_tlv(&mut self) -> Result<Option<(u8, &'a [u8])>, Error> {
		if self.position + 3 > self.data.len() {
			return Ok(None);
		}

		let tag = self.data[self.position];
		let len = u16::from_be_bytes([self.data[self.position + 1], self.data[self.position + 2]])
			as usize;
		self.position += 3;

		if self.position + len > self.data.len() {
			return Err(Error::InvalidLength);
		}

		let value = &self.data[self.position..self.position + len];
		self.position += len;

		Ok(Some((tag, value)))
	}
}

/// Helper to write TLV (Tag-Length-Value) data directly to a buffer.
///
/// For nested TLVs, use [`SingleTlvWriter`] which provides RAII-based length patching.
/// This avoids intermediate allocations by writing directly to a single buffer and
/// patching the length field when the wrapper is dropped.
struct TlvWriter {
	data: Vec<u8>,
}

impl TlvWriter {
	fn with_capacity(capacity: usize) -> Self {
		Self { data: Vec::with_capacity(capacity) }
	}

	fn write_tlv(&mut self, tag: u8, value: &[u8]) {
		self.data.push(tag);
		let len = value.len() as u16;
		self.data.extend_from_slice(&len.to_be_bytes());
		self.data.extend_from_slice(value);
	}

	/// Write raw bytes directly to the buffer (used for tag tuple encoding).
	fn write_raw(&mut self, bytes: &[u8]) {
		self.data.extend_from_slice(bytes);
	}

	/// Write a single byte directly to the buffer.
	fn write_byte(&mut self, byte: u8) {
		self.data.push(byte);
	}

	fn into_bytes(self) -> Vec<u8> {
		self.data
	}
}

/// Wrapper for writing a single nested TLV structure.
/// Writes the tag and length placeholder on creation, patches the length on drop.
struct SingleTlvWriter<'a> {
	writer: &'a mut TlvWriter,
	len_pos: usize,
}

impl<'a> SingleTlvWriter<'a> {
	fn new(writer: &'a mut TlvWriter, tag: u8) -> Self {
		writer.data.push(tag);
		let len_pos = writer.data.len();
		writer.data.extend_from_slice(&[0, 0]); // Placeholder for length
		Self { writer, len_pos }
	}

	/// Create a nested TLV writer within this one.
	fn nested(&mut self, tag: u8) -> SingleTlvWriter<'_> {
		SingleTlvWriter::new(self.writer, tag)
	}

	fn write_tlv(&mut self, tag: u8, value: &[u8]) {
		self.writer.write_tlv(tag, value);
	}

	fn write_raw(&mut self, bytes: &[u8]) {
		self.writer.write_raw(bytes);
	}

	fn write_byte(&mut self, byte: u8) {
		self.writer.write_byte(byte);
	}
}

impl Drop for SingleTlvWriter<'_> {
	fn drop(&mut self) {
		let value_len = self.writer.data.len() - (self.len_pos + 2);
		let len_bytes = (value_len as u16).to_be_bytes();
		self.writer.data[self.len_pos] = len_bytes[0];
		self.writer.data[self.len_pos + 1] = len_bytes[1];
	}
}

impl FromStr for CashuPaymentRequest {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_bech32_string(s)
	}
}

impl fmt::Display for CashuPaymentRequest {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let s = self.to_bech32_string().map_err(|_| fmt::Error)?;
		f.write_str(&s)
	}
}

impl CashuPaymentRequest {
	/// Encodes a payment request to CREQB1 bech32m format.
	///
	/// # Example
	///
	/// ```
	/// use bitcoin_payment_instructions::cashu::{CashuPaymentRequest, CurrencyUnit};
	///
	/// let request = CashuPaymentRequest {
	///     payment_id: Some("demo123".to_string()),
	///     amount: Some(1000),
	///     unit: Some(CurrencyUnit::Sat),
	///     single_use: Some(true),
	///     mints: Some(vec!["https://mint.example.com".to_string()]),
	///     description: Some("Coffee payment".to_string()),
	///     transports: vec![],
	///     nut10: None,
	/// };
	///
	/// let encoded = request.to_bech32_string().unwrap();
	/// assert!(encoded.starts_with("CREQB1"));
	/// ```
	pub fn to_bech32_string(&self) -> Result<String, Error> {
		let tlv_bytes = self.encode_tlv()?;
		let hrp = Hrp::parse(CREQ_B_HRP).map_err(|_| Error::InvalidPrefix)?;

		// Always emit uppercase for QR compatibility
		let encoded =
			bech32::encode_upper::<Bech32m>(hrp, &tlv_bytes).map_err(|_| Error::Bech32)?;
		Ok(encoded)
	}

	/// Decodes a payment request from CREQB1 bech32m format.
	pub fn from_bech32_string(s: &str) -> Result<Self, Error> {
		// If s contains ':', assume it might be a URI and try to extract the bech32 part?
		// But the caller usually handles URIs. We assume s is the bech32 string.
		let (hrp, data) = bech32::decode(s).map_err(|_| Error::Bech32)?;
		if !hrp.as_str().eq_ignore_ascii_case(CREQ_B_HRP) {
			return Err(Error::InvalidPrefix);
		}

		Self::from_bech32_bytes(&data)
	}

	#[cfg(fuzzing)]
	/// Decode from a byte array so the fuzzer can bypass bech32
	pub fn from_bytes_fuzzy(bytes: &[u8]) -> Result<CashuPaymentRequest, Error> {
		Self::from_bech32_bytes(bytes)
	}

	/// Decode from TLV bytes
	fn from_bech32_bytes(bytes: &[u8]) -> Result<CashuPaymentRequest, Error> {
		let mut reader = TlvReader::new(bytes);

		let mut id: Option<String> = None;
		let mut amount: Option<u64> = None;
		let mut unit: Option<CurrencyUnit> = None;
		let mut single_use: Option<bool> = None;
		let mut mints: Vec<String> = Vec::new();
		let mut description: Option<String> = None;
		let mut transports: Vec<Transport> = Vec::new();
		let mut nut10: Option<Nut10SecretRequest> = None;

		while let Some((tag, value)) = reader.read_tlv()? {
			match tag {
				0x01 => {
					// id: string
					if id.is_some() {
						return Err(Error::InvalidStructure);
					}
					id = Some(String::from_utf8(value.to_vec()).map_err(|_| Error::InvalidUtf8)?);
				},
				0x02 => {
					// amount: u64
					if amount.is_some() {
						return Err(Error::InvalidStructure);
					}
					if value.len() != 8 {
						return Err(Error::InvalidLength);
					}
					let amount_val = u64::from_be_bytes([
						value[0], value[1], value[2], value[3], value[4], value[5], value[6],
						value[7],
					]);
					amount = Some(amount_val);
				},
				0x03 => {
					// unit: u8 or string
					if unit.is_some() {
						return Err(Error::InvalidStructure);
					}
					if value.len() == 1 && value[0] == 0 {
						unit = Some(CurrencyUnit::Sat);
					} else {
						match value {
							b"msat" => unit = Some(CurrencyUnit::Msat),
							b"usd" => unit = Some(CurrencyUnit::Usd),
							b"eur" => unit = Some(CurrencyUnit::Eur),
							b"auth" => unit = Some(CurrencyUnit::Auth),
							_ => {
								let unit_str =
									UnitString::from_utf8(value).ok_or(Error::InvalidUtf8)?;
								unit = Some(CurrencyUnit::Custom(unit_str));
							},
						}
					}
				},
				0x04 => {
					// single_use: u8 (0 or 1)
					if single_use.is_some() {
						return Err(Error::InvalidStructure);
					}
					if !value.is_empty() {
						single_use = Some(value[0] != 0);
					}
				},
				0x05 => {
					// mint: string (repeatable)
					let mint_str =
						String::from_utf8(value.to_vec()).map_err(|_| Error::InvalidUtf8)?;
					mints.push(mint_str);
				},
				0x06 => {
					// description: string
					if description.is_some() {
						return Err(Error::InvalidStructure);
					}
					description =
						Some(String::from_utf8(value.to_vec()).map_err(|_| Error::InvalidUtf8)?);
				},
				0x07 => {
					// transport: sub-TLV (repeatable)
					let transport = Self::decode_transport(value)?;
					transports.push(transport);
				},
				0x08 => {
					// nut10: sub-TLV
					if nut10.is_some() {
						return Err(Error::InvalidStructure);
					}
					nut10 = Some(Self::decode_nut10(value)?);
				},
				_ => {
					// Unknown tags are ignored
				},
			}
		}

		Ok(CashuPaymentRequest {
			payment_id: id,
			amount,
			unit,
			single_use,
			mints: if mints.is_empty() { None } else { Some(mints) },
			description,
			transports,
			nut10,
		})
	}

	/// Encode to TLV bytes
	fn encode_tlv(&self) -> Result<Vec<u8>, Error> {
		// Estimate capacity to minimize reallocations:
		// - Each TLV header is 3 bytes (1 tag + 2 length)
		// - id: ~10-50 bytes typical
		// - amount: 8 bytes
		// - unit: 1-10 bytes
		// - single_use: 1 byte
		// - mints: variable, ~50 bytes each
		// - description: variable
		// - transports: ~100-200 bytes each
		// - nut10: ~100 bytes
		let estimated_capacity = 64
			+ self.payment_id.as_ref().map_or(0, |s| s.len() + 3)
			+ self.amount.map_or(0, |_| 11)
			+ self.unit.as_ref().map_or(0, |_| 10)
			+ self.mints.as_ref().map_or(0, |m| m.iter().map(|s| s.len() + 3).sum())
			+ self.description.as_ref().map_or(0, |s| s.len() + 3)
			+ self.transports.len() * 150
			+ self.nut10.as_ref().map_or(0, |_| 100);

		let mut writer = TlvWriter::with_capacity(estimated_capacity);

		// 0x01 id: string
		if let Some(ref id) = self.payment_id {
			writer.write_tlv(0x01, id.as_bytes());
		}

		// 0x02 amount: u64
		if let Some(amount) = self.amount {
			let amount_bytes = amount.to_be_bytes();
			writer.write_tlv(0x02, &amount_bytes);
		}

		// 0x03 unit: u8 or string
		if let Some(ref unit) = self.unit {
			match unit {
				CurrencyUnit::Sat => writer.write_tlv(0x03, &[0]),
				CurrencyUnit::Msat => writer.write_tlv(0x03, b"msat"),
				CurrencyUnit::Usd => writer.write_tlv(0x03, b"usd"),
				CurrencyUnit::Eur => writer.write_tlv(0x03, b"eur"),
				CurrencyUnit::Auth => writer.write_tlv(0x03, b"auth"),
				CurrencyUnit::Custom(s) => writer.write_tlv(0x03, s.as_bytes()),
			}
		}

		// 0x04 single_use: u8 (0 or 1)
		if let Some(single_use) = self.single_use {
			writer.write_tlv(0x04, &[if single_use { 1 } else { 0 }]);
		}

		// 0x05 mint: string (repeatable)
		if let Some(ref mints) = self.mints {
			for mint in mints {
				writer.write_tlv(0x05, mint.as_bytes());
			}
		}

		// 0x06 description: string
		if let Some(ref description) = self.description {
			writer.write_tlv(0x06, description.as_bytes());
		}

		// 0x07 transport: sub-TLV (repeatable, order = priority)
		for transport in &self.transports {
			let mut w = SingleTlvWriter::new(&mut writer, 0x07);
			Self::encode_transport_into(transport, &mut w)?;
		}

		// 0x08 nut10: sub-TLV
		if let Some(ref nut10) = self.nut10 {
			let mut w = SingleTlvWriter::new(&mut writer, 0x08);
			Self::encode_nut10_into(nut10, &mut w)?;
		}

		Ok(writer.into_bytes())
	}

	/// Decode transport sub-TLV
	fn decode_transport(bytes: &[u8]) -> Result<Transport, Error> {
		let mut reader = TlvReader::new(bytes);

		let mut kind: Option<u8> = None;
		let mut raw_target: Option<&[u8]> = None;
		let mut tags: Vec<(&str, Vec<&str>)> = Vec::new();

		while let Some((tag, value)) = reader.read_tlv()? {
			match tag {
				0x01 => {
					// kind: u8
					if kind.is_some() {
						return Err(Error::InvalidStructure);
					}
					if value.len() != 1 {
						return Err(Error::InvalidLength);
					}
					kind = Some(value[0]);
				},
				0x02 => {
					// target: bytes (store raw, interpret after loop based on kind)
					if raw_target.is_some() {
						return Err(Error::InvalidStructure);
					}
					raw_target = Some(value);
				},
				0x03 => {
					// tag_tuple: generic tuple (repeatable)
					let tag_tuple = Self::decode_tag_tuple(value)?;
					tags.push(tag_tuple);
				},
				_ => {
					// Unknown sub-TLV tags are ignored
				},
			}
		}

		let transport_type = match kind.ok_or(Error::InvalidStructure)? {
			0x00 => TransportType::Nostr,
			0x01 => TransportType::HttpPost,
			_ => return Err(Error::InvalidStructure),
		};

		let relays: Vec<&str> =
			tags.iter().filter(|(k, _)| *k == "r").flat_map(|(_, v)| v.iter().copied()).collect();

		// Interpret raw target bytes based on kind
		let raw_target = raw_target.ok_or(Error::InvalidStructure)?;
		let target = match transport_type {
			TransportType::Nostr => {
				// nostr: 32-byte x-only pubkey
				if raw_target.len() != 32 {
					return Err(Error::InvalidLength);
				}
				Self::encode_nprofile(raw_target, &relays)?
			},
			TransportType::HttpPost => {
				// http_post: UTF-8 URL string
				String::from_utf8(raw_target.to_vec()).map_err(|_| Error::InvalidUtf8)?
			},
		};

		let mut final_tags: Vec<TagTuple> = Vec::new();
		for (key, values) in tags {
			if key != "r" {
				final_tags.push(TagTuple::new(key, values)?);
			}
		}

		Ok(Transport { kind: transport_type, target, tags: final_tags })
	}

	/// Encode transport body directly into the provided writer to avoid intermediate allocations.
	fn encode_transport_into(
		transport: &Transport, writer: &mut SingleTlvWriter<'_>,
	) -> Result<(), Error> {
		let kind = match transport.kind {
			TransportType::Nostr => 0x00u8,
			TransportType::HttpPost => 0x01u8,
		};
		writer.write_tlv(0x01, &[kind]);

		match transport.kind {
			TransportType::Nostr => {
				let (pubkey, relays) = Self::decode_nprofile(&transport.target)?;

				writer.write_tlv(0x02, &pubkey);

				for tag in transport.tags.iter() {
					Self::encode_tag_tuple_into(tag, writer);
				}

				for relay in relays {
					Self::encode_tag_tuple_into(&TagTuple::single("r", &relay)?, writer);
				}
			},
			TransportType::HttpPost => {
				writer.write_tlv(0x02, transport.target.as_bytes());

				for tag in transport.tags.iter() {
					Self::encode_tag_tuple_into(tag, writer);
				}
			},
		}

		Ok(())
	}

	/// Decode NUT-10 sub-TLV
	fn decode_nut10(bytes: &[u8]) -> Result<Nut10SecretRequest, Error> {
		let mut reader = TlvReader::new(bytes);

		let mut kind: Option<u8> = None;
		let mut data: Option<Vec<u8>> = None;
		let mut tags: Vec<TagTuple> = Vec::new();

		while let Some((tag, value)) = reader.read_tlv()? {
			match tag {
				0x01 => {
					// kind: u8
					if kind.is_some() {
						return Err(Error::InvalidStructure);
					}
					if value.len() != 1 {
						return Err(Error::InvalidLength);
					}
					kind = Some(value[0]);
				},
				0x02 => {
					// data: bytes
					if data.is_some() {
						return Err(Error::InvalidStructure);
					}
					data = Some(value.to_vec());
				},
				0x03 | 0x05 => {
					// tag_tuple: generic tuple (repeatable)
					let (key, values) = Self::decode_tag_tuple(value)?;
					tags.push(TagTuple::new(key, values)?);
				},
				_ => {
					// Unknown tags are ignored
				},
			}
		}

		let kind_val = kind.ok_or(Error::InvalidStructure)?;
		let data_val = data.unwrap_or_default();

		let data_str = String::from_utf8(data_val).map_err(|_| Error::InvalidUtf8)?;

		let kind_enum = match kind_val {
			0 => Kind::P2PK,
			1 => Kind::HTLC,
			_ => return Err(Error::UnknownKind(kind_val)),
		};

		Ok(Nut10SecretRequest::new(kind_enum, &data_str, tags))
	}

	/// Encode NUT-10 body directly into the provided writer to avoid intermediate allocations.
	fn encode_nut10_into(
		nut10: &Nut10SecretRequest, writer: &mut SingleTlvWriter<'_>,
	) -> Result<(), Error> {
		let kind_val = match nut10.kind {
			Kind::P2PK => 0u8,
			Kind::HTLC => 1u8,
		};
		writer.write_tlv(0x01, &[kind_val]);
		writer.write_tlv(0x02, nut10.data.as_bytes());

		for tag in nut10.tags.iter() {
			Self::encode_tag_tuple_into(tag, writer);
		}

		Ok(())
	}

	/// Decode tag tuple, returning borrowed strings to avoid intermediate allocations.
	fn decode_tag_tuple(bytes: &[u8]) -> Result<(&str, Vec<&str>), Error> {
		if bytes.is_empty() {
			return Err(Error::InvalidLength);
		}

		let key_len = bytes[0] as usize;
		if bytes.len() < 1 + key_len {
			return Err(Error::InvalidLength);
		}

		let key = core::str::from_utf8(&bytes[1..1 + key_len]).map_err(|_| Error::InvalidUtf8)?;

		let mut values = Vec::new();
		let mut pos = 1 + key_len;

		while pos < bytes.len() {
			let val_len = bytes[pos] as usize;
			pos += 1;

			if pos + val_len > bytes.len() {
				return Err(Error::InvalidLength);
			}

			let value =
				core::str::from_utf8(&bytes[pos..pos + val_len]).map_err(|_| Error::InvalidUtf8)?;
			values.push(value);
			pos += val_len;
		}

		Ok((key, values))
	}

	/// Encode tag tuple directly into the provided writer to avoid intermediate allocations.
	/// Writes as a 0x03 sub-TLV (tag + length + key/values).
	fn encode_tag_tuple_into(tag: &TagTuple, writer: &mut SingleTlvWriter<'_>) {
		let mut w = writer.nested(0x03);

		// Key length + key
		w.write_byte(tag.key().len() as u8);
		w.write_raw(tag.key().as_bytes());

		// Values
		for value in tag.values() {
			w.write_byte(value.len() as u8);
			w.write_raw(value.as_bytes());
		}
	}

	/// Decode nprofile bech32 string to (pubkey, relays)
	fn decode_nprofile(nprofile: &str) -> Result<([u8; 32], Vec<String>), Error> {
		let (hrp, data) = bech32::decode(nprofile).map_err(|_| Error::Bech32)?;
		if hrp.as_str() != "nprofile" {
			return Err(Error::InvalidPrefix);
		}

		let mut pos = 0;
		let mut pubkey: Option<[u8; 32]> = None;
		let mut relays: Vec<String> = Vec::new();

		while pos < data.len() {
			if pos + 2 > data.len() {
				break;
			}

			let tag = data[pos];
			let len = data[pos + 1] as usize;
			pos += 2;

			if pos + len > data.len() {
				return Err(Error::InvalidLength);
			}

			let value = &data[pos..pos + len];
			pos += len;

			match tag {
				0 => {
					// pubkey: 32 bytes
					if value.len() != 32 {
						return Err(Error::InvalidLength);
					}
					pubkey = Some(value.try_into().expect("len is 32"));
				},
				1 => {
					// relay: UTF-8 string
					let relay =
						String::from_utf8(value.to_vec()).map_err(|_| Error::InvalidUtf8)?;
					relays.push(relay);
				},
				_ => {
					// Unknown TLV types are ignored
				},
			}
		}

		let pubkey = pubkey.ok_or(Error::InvalidStructure)?;
		Ok((pubkey, relays))
	}

	/// Encode pubkey and relays to nprofile bech32 string
	fn encode_nprofile(pubkey: &[u8], relays: &[&str]) -> Result<String, Error> {
		if pubkey.len() != 32 {
			return Err(Error::InvalidLength);
		}

		let capacity = 34 + relays.iter().map(|r| 2 + r.len()).sum::<usize>();
		let mut tlv_bytes = Vec::with_capacity(capacity);

		// Type 0: pubkey (32 bytes)
		tlv_bytes.push(0);
		tlv_bytes.push(32);
		tlv_bytes.extend_from_slice(pubkey);

		// Type 1: relays
		for relay in relays {
			if relay.len() > 255 {
				return Err(Error::InvalidLength);
			}
			tlv_bytes.push(1);
			tlv_bytes.push(relay.len() as u8);
			tlv_bytes.extend_from_slice(relay.as_bytes());
		}

		let hrp = Hrp::parse("nprofile").map_err(|_| Error::InvalidPrefix)?;
		bech32::encode::<bech32::Bech32>(hrp, &tlv_bytes).map_err(|_| Error::Bech32)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::string::ToString;
	use bitcoin::hex::FromHex;

	#[test]
	fn test_bech32_basic_round_trip() {
		let transport = Transport {
			kind: TransportType::HttpPost,
			target: "https://api.example.com/payment".to_string(),
			tags: Vec::new(),
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("test123".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: Some(true),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Test payment".to_string()),
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify it starts with CREQB1
		assert!(encoded.starts_with("CREQB1"));

		// Round-trip test
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");
		assert_eq!(decoded.payment_id, payment_request.payment_id);
		assert_eq!(decoded.amount, payment_request.amount);
		assert_eq!(decoded.unit, payment_request.unit);
		assert_eq!(decoded.single_use, payment_request.single_use);
		assert_eq!(decoded.description, payment_request.description);
	}

	#[test]
	fn test_bech32_minimal() {
		let payment_request = CashuPaymentRequest {
			payment_id: Some("minimal".to_string()),
			amount: None,
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");
		assert_eq!(decoded.payment_id, payment_request.payment_id);
		assert_eq!(decoded.mints, payment_request.mints);
	}

	#[test]
	fn test_bech32_with_nut10() {
		let nut10 = Nut10SecretRequest::new(
			Kind::P2PK,
			"026562efcfadc8e86d44da6a8adf80633d974302e62c850774db1fb36ff4cc7198",
			vec![TagTuple::single("timeout", "3600").unwrap()],
		);

		let payment_request = CashuPaymentRequest {
			payment_id: Some("nut10test".to_string()),
			amount: Some(500),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("P2PK locked payment".to_string()),
			transports: vec![],
			nut10: Some(nut10.clone()),
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");
		assert_eq!(decoded.nut10.as_ref().unwrap().kind, nut10.kind);
		assert_eq!(decoded.nut10.as_ref().unwrap().data, nut10.data);
	}

	#[test]
	fn test_parse_creq_param_bech32() {
		let payment_request = CashuPaymentRequest {
			payment_id: Some("test123".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded_payment_request =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("should parse bech32");
		assert_eq!(decoded_payment_request.payment_id, payment_request.payment_id);
	}

	#[test]
	fn test_from_bech32_string_errors_on_wrong_encoding() {
		// Test that from_bech32_string errors if given a non-CREQ-B string
		let legacy_creq = "creqApWF0gaNhdGVub3N0cmFheKlucHJvZmlsZTFxeTI4d3VtbjhnaGo3dW45ZDNzaGp0bnl2OWtoMnVld2Q5aHN6OW1od2RlbjV0ZTB3ZmprY2N0ZTljdXJ4dmVuOWVlaHFjdHJ2NWhzenJ0aHdkZW41dGUwZGVoaHh0bnZkYWtxcWd5ZGFxeTdjdXJrNDM5eWtwdGt5c3Y3dWRoZGh1NjhzdWNtMjk1YWtxZWZkZWhrZjBkNDk1Y3d1bmw1YWeBgmFuYjE3YWloYjdhOTAxNzZhYQphdWNzYXRhbYF4Imh0dHBzOi8vbm9mZWVzLnRlc3RudXQuY2FzaHUuc3BhY2U=";

		// Should error because it's not bech32m encoded
		assert!(CashuPaymentRequest::from_bech32_string(legacy_creq).is_err());

		// Test with a string that's not CREQ-B
		assert!(CashuPaymentRequest::from_bech32_string("not_a_creq").is_err());

		// Test with wrong HRP (nprofile instead of creqb)
		let pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey_bytes = Vec::<u8>::from_hex(pubkey_hex).unwrap();
		let nprofile = CashuPaymentRequest::encode_nprofile(&pubkey_bytes, &[])
			.expect("should encode nprofile");
		assert!(CashuPaymentRequest::from_bech32_string(&nprofile).is_err());
	}

	#[test]
	fn test_unit_encoding_bech32() {
		// Test default sat unit
		let payment_request = CashuPaymentRequest {
			payment_id: Some("unit_test".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");
		assert_eq!(decoded.unit, Some(CurrencyUnit::Sat));

		// Test custom unit
		let payment_request_usd = CashuPaymentRequest {
			payment_id: Some("unit_test_usd".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Usd),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded_usd = payment_request_usd.to_bech32_string().expect("encoding should work");

		let decoded_usd =
			CashuPaymentRequest::from_bech32_string(&encoded_usd).expect("decoding should work");
		assert_eq!(decoded_usd.unit, Some(CurrencyUnit::Usd));
	}

	#[test]
	fn test_nprofile_no_relays() {
		// Test vector: a known 32-byte pubkey
		let pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey_bytes = Vec::<u8>::from_hex(pubkey_hex).unwrap();

		// Encode to nprofile with empty relay list
		let nprofile = CashuPaymentRequest::encode_nprofile(&pubkey_bytes, &[])
			.expect("should encode nprofile");
		assert!(nprofile.starts_with("nprofile"));

		// Decode back
		let decoded =
			CashuPaymentRequest::decode_nprofile(&nprofile).expect("should decode nprofile");
		assert_eq!(&decoded.0[..], &pubkey_bytes[..]);
		assert!(decoded.1.is_empty());
	}

	#[test]
	fn test_nostr_transport_with_nprofile_no_relays() {
		// Create a payment request with nostr transport using nprofile with empty relay list
		let pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey_bytes = Vec::<u8>::from_hex(pubkey_hex).unwrap();
		let nprofile =
			CashuPaymentRequest::encode_nprofile(&pubkey_bytes, &[]).expect("encode nprofile");

		let transport = Transport {
			kind: TransportType::Nostr,
			target: nprofile.clone(),
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("nostr_test".to_string()),
			amount: Some(1000),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Nostr payment".to_string()),
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.payment_id, payment_request.payment_id);
		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);
		assert!(decoded.transports[0].target.starts_with("nprofile"));

		// Check that NIP-17 tag was preserved
		let mut tags_iter = decoded.transports[0].tags.iter();
		assert!(
			tags_iter.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("17"))
		);
	}

	#[test]
	fn test_nostr_transport_with_nprofile() {
		// Create a payment request with nostr transport using nprofile
		let pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey_bytes = Vec::<u8>::from_hex(pubkey_hex).unwrap();
		let relays: Vec<&str> = vec!["wss://relay.example.com"];
		let nprofile =
			CashuPaymentRequest::encode_nprofile(&pubkey_bytes, &relays).expect("encode nprofile");

		let transport = Transport {
			kind: TransportType::Nostr,
			target: nprofile.clone(),
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("nprofile_test".to_string()),
			amount: Some(2100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Nostr payment with relays".to_string()),
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.payment_id, payment_request.payment_id);
		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);

		// Should be encoded back as nprofile since it has relays
		assert!(decoded.transports[0].target.starts_with("nprofile"));

		// Check that relay was preserved
		let relays = decoded.transports[0].nostr_relays().unwrap();
		assert_eq!(relays[0].as_str(), "wss://relay.example.com");
	}

	#[test]
	fn test_spec_example_nostr_transport() {
		// Test a complete example as specified in the spec:
		// Payment request with nostr transport, NIP-17, pubkey, and one relay
		let pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey_bytes = Vec::<u8>::from_hex(pubkey_hex).unwrap();
		let relays: Vec<&str> = vec!["wss://relay.damus.io"];
		let nprofile =
			CashuPaymentRequest::encode_nprofile(&pubkey_bytes, &relays).expect("encode nprofile");

		let transport = Transport {
			kind: TransportType::Nostr,
			target: nprofile,
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("spec_example".to_string()),
			amount: Some(10),
			unit: Some(CurrencyUnit::Sat),
			single_use: Some(true),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Coffee".to_string()),
			transports: vec![transport],
			nut10: None,
		};

		// Encode and decode
		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		// Verify round-trip
		assert_eq!(decoded.payment_id, Some("spec_example".to_string()));
		assert_eq!(decoded.amount, Some(10));
		assert_eq!(decoded.unit, Some(CurrencyUnit::Sat));
		assert_eq!(decoded.single_use, Some(true));
		assert_eq!(decoded.description, Some("Coffee".to_string()));
		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);

		// Verify relay and NIP are preserved
		let mut tags_iter = decoded.transports[0].tags.iter();
		assert!(
			tags_iter.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("17"))
		);

		let nostr_relays = decoded.transports[0].nostr_relays().unwrap();
		assert_eq!(nostr_relays[0].as_str(), "wss://relay.damus.io");
	}

	#[test]
	fn test_decode_valid_bech32_with_nostr_pubkeys_and_mints() {
		// First, create a payment request with multiple mints and nostr transports with different pubkeys
		let pubkey1_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
		let pubkey1_bytes = Vec::<u8>::from_hex(pubkey1_hex).unwrap();
		// Use nprofile with empty relay list instead of npub
		let nprofile1 =
			CashuPaymentRequest::encode_nprofile(&pubkey1_bytes, &[]).expect("encode nprofile1");

		let pubkey2_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
		let pubkey2_bytes = Vec::<u8>::from_hex(pubkey2_hex).unwrap();
		let relays2: Vec<&str> = vec!["wss://relay.damus.io", "wss://nos.lol"];
		let nprofile2 = CashuPaymentRequest::encode_nprofile(&pubkey2_bytes, &relays2)
			.expect("encode nprofile2");

		let transport1 = Transport {
			kind: TransportType::Nostr,
			target: nprofile1.clone(),
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};

		let transport2 = Transport {
			kind: TransportType::Nostr,
			target: nprofile2.clone(),
			tags: vec![TagTuple::single("n", "17").unwrap(), TagTuple::single("n", "44").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("multi_test".to_string()),
			amount: Some(5000),
			unit: Some(CurrencyUnit::Sat),
			single_use: Some(false),
			mints: Some(vec![
				"https://mint1.example.com".to_string(),
				"https://mint2.example.com".to_string(),
				"https://testnut.cashu.space".to_string(),
			]),
			description: Some("Payment with multiple transports and mints".to_string()),
			transports: vec![transport1, transport2],
			nut10: None,
		};

		// Encode to bech32 string
		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Now decode the bech32 string and verify contents
		let decoded = CashuPaymentRequest::from_bech32_string(&encoded)
			.expect("should decode valid bech32 string");

		// Verify basic fields
		assert_eq!(decoded.payment_id, Some("multi_test".to_string()));
		assert_eq!(decoded.amount, Some(5000));
		assert_eq!(decoded.unit, Some(CurrencyUnit::Sat));
		assert_eq!(decoded.single_use, Some(false));
		assert_eq!(
			decoded.description,
			Some("Payment with multiple transports and mints".to_string())
		);

		// Verify mints
		let mints = decoded.mints.as_ref().expect("should have mints");
		assert_eq!(mints.len(), 3);

		// Verify transports
		assert_eq!(decoded.transports.len(), 2);

		// Verify first transport (nprofile with no relays)
		let transport1_decoded = &decoded.transports[0];
		assert_eq!(transport1_decoded.kind, TransportType::Nostr);
		assert!(transport1_decoded.target.starts_with("nprofile"));

		// Decode the nprofile to verify the pubkey
		let (decoded_pubkey1, decoded_relays1) =
			CashuPaymentRequest::decode_nprofile(&transport1_decoded.target)
				.expect("should decode nprofile");
		assert_eq!(&decoded_pubkey1[..], &pubkey1_bytes[..]);
		assert!(decoded_relays1.is_empty());

		// Verify NIP-17 tag
		let mut tags1_iter = transport1_decoded.tags.iter();
		assert!(
			tags1_iter.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("17"))
		);

		// Verify second transport (nprofile)
		let transport2_decoded = &decoded.transports[1];
		assert_eq!(transport2_decoded.kind, TransportType::Nostr);
		assert!(transport2_decoded.target.starts_with("nprofile"));

		// Decode the nprofile to verify the pubkey and relays
		let (decoded_pubkey2, decoded_relays2) =
			CashuPaymentRequest::decode_nprofile(&transport2_decoded.target)
				.expect("should decode nprofile");
		assert_eq!(&decoded_pubkey2[..], &pubkey2_bytes[..]);
		assert_eq!(decoded_relays2, relays2);

		// Verify tags include both NIPs and relays
		let tags2 = &transport2_decoded.tags;
		assert!(tags2
			.iter()
			.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("17")));
		assert!(tags2
			.iter()
			.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("44")));
		let relays = transport2_decoded.nostr_relays().unwrap();
		assert!(relays.iter().any(|v| v == "wss://relay.damus.io"));
		assert!(relays.iter().any(|v| v == "wss://nos.lol"));
	}

	#[test]
	fn test_basic_payment_request() {
		// Basic payment request with required fields
		// Original JSON:
		// {
		//     "i": "b7a90176",
		//     "a": 10,
		//     "u": "sat",
		//     "m": ["https://8333.space:3338"],
		//     "t": [
		//         {
		//             "t": "nostr",
		//             "a": "nprofile1qqsgm6qfa3c8dtz2fvzhvfqeacmwm0e50pe3k5tfmvpjjmn0vj7m2tgpz3mhxue69uhhyetvv9ujuerpd46hxtnfduq3wamnwvaz7tmjv4kxz7fw8qenxvewwdcxzcm99uqs6amnwvaz7tmwdaejumr0ds4ljh7n",
		//             "g": [["n", "17"]]
		//         }
		//     ]
		// }

		let expected_encoded = "CREQB1QYQQSC3HVYUNQVFHXCPQQZQQQQQQQQQQQQ9QXQQPQQZSQ9MGW368QUE69UHNSVENXVH8XURPVDJN5VENXVUQWQREQYQQZQQZQQSGM6QFA3C8DTZ2FVZHVFQEACMWM0E50PE3K5TFMVPJJMN0VJ7M2TGRQQZSZMSZXYMSXQQHQ9EPGAMNWVAZ7TMJV4KXZ7FWV3SK6ATN9E5K7QCQRGQHY9MHWDEN5TE0WFJKCCTE9CURXVEN9EEHQCTRV5HSXQQSQ9EQ6AMNWVAZ7TMWDAEJUMR0DSRYDPGF";

		// Construct the struct manually
		let transport = Transport {
			kind: TransportType::Nostr,
			target: "nprofile1qqsgm6qfa3c8dtz2fvzhvfqeacmwm0e50pe3k5tfmvpjjmn0vj7m2tgpz3mhxue69uhhyetvv9ujuerpd46hxtnfduq3wamnwvaz7tmjv4kxz7fw8qenxvewwdcxzcm99uqs6amnwvaz7tmwdaejumr0ds4ljh7n".to_string(),
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("b7a90176".to_string()),
			amount: Some(10),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://8333.space:3338".to_string()]),
			description: None,
			transports: vec![transport],
			nut10: None,
		};

		// Test bech32m encoding (CREQ-B format)
		let encoded = payment_request.to_bech32_string().expect("Failed to encode to bech32");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Test round-trip via bech32 format
		let decoded = CashuPaymentRequest::from_bech32_string(&encoded).unwrap();

		// Verify decoded fields match original
		assert_eq!(decoded.payment_id.as_ref().unwrap(), "b7a90176");
		assert_eq!(decoded.amount.unwrap(), 10);
		assert_eq!(decoded.unit.unwrap(), CurrencyUnit::Sat);
		assert_eq!(decoded.mints.unwrap(), vec!["https://8333.space:3338".to_string()]);

		// Verify transport type and that it has the NIP-17 tag
		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);
		let mut tags_iter = decoded.transports[0].tags.iter();
		assert!(
			tags_iter.any(|t| t.key == "n" && t.values.first().map(|s| s.as_str()) == Some("17"))
		);
	}

	#[test]
	fn test_nostr_transport_payment_request() {
		let expected_encoded = "CREQB1QYQQSE3EXFSN2VTZ8QPQQZQQQQQQQQQQQPJQXQQPQQZSQXTGW368QUE69UHK66TWWSCJUETCV9KHQMR99E3K7MG9QQVKSAR5WPEN5TE0D45KUAPJ9EJHSCTDWPKX2TNRDAKSWQPEQYQQZQQZQQSQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQRQQZSZMSZXYMSXQQ8Q9HQGWFHXV6SCAGZ48";

		let transport = Transport {
			kind: TransportType::Nostr,
			target: "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt"
				.to_string(),
			tags: vec![
				TagTuple::single("n", "17").unwrap(),
				TagTuple::single("n", "9735").unwrap(),
			],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("f92a51b8".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec![
				"https://mint1.example.com".to_string(),
				"https://mint2.example.com".to_string(),
			]),
			description: None,
			transports: vec![transport],
			nut10: None,
		};

		// Test round-trip serialization
		let encoded = payment_request.to_bech32_string().unwrap();

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		let decoded = CashuPaymentRequest::from_bech32_string(&encoded).unwrap();
		assert_eq!(payment_request, decoded);
	}

	#[test]
	fn test_minimal_payment_request_vectors() {
		let expected_encoded =
			"CREQB1QYQQSDMXX3SNYC3N8YPSQQGQQ5QPS6R5W3C8XW309AKKJMN59EJHSCTDWPKX2TNRDAKSYP0LHG";

		let payment_request = CashuPaymentRequest {
			payment_id: Some("7f4a2b39".to_string()),
			amount: None,
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		// Test round-trip serialization
		let encoded = payment_request.to_bech32_string().unwrap();
		assert_eq!(encoded, expected_encoded);
		let decoded = CashuPaymentRequest::from_bech32_string(&encoded).unwrap();
		assert_eq!(payment_request, decoded);
	}

	#[test]
	fn test_nut10_locking_payment_request_vectors() {
		let expected_encoded = "CREQB1QYQQSCEEV56R2EPJVYPQQZQQQQQQQQQQQ86QXQQPQQZSQXRGW368QUE69UHK66TWWSHX27RPD4CXCEFWVDHK6ZQQTYQSQQGQQGQYYVPJVVEKYDTZVGERWEFNXCCNGDFHVVUNYEPEXDJRWWRYVSMNXEPNVS6NXDENXGCNZVRZXF3KVEFCVG6NQENZVVCXZCNRXCCN2EFEVVENXVGRQQXSWARFD4JK7AT5QSENVVPS2N5FAS";

		let nut10 = Nut10SecretRequest {
			kind: Kind::P2PK,
			data: "02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331".to_string(),
			tags: vec![TagTuple::single("timeout", "3600").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("c9e45d2a".to_string()),
			amount: Some(500),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: Some(nut10),
		};

		// Test round-trip serialization
		let encoded = payment_request.to_bech32_string().unwrap();
		assert_eq!(encoded, expected_encoded);
		let decoded = CashuPaymentRequest::from_bech32_string(&encoded).unwrap();
		assert_eq!(payment_request, decoded);
	}

	#[test]
	fn test_nut26_example() {
		let expected_encoded = "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQVXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YPCXZ7TDV4H8GXHR3TQ";

		let payment_request = CashuPaymentRequest {
			payment_id: Some("demo123".to_string()),
			amount: Some(1000),
			unit: Some(CurrencyUnit::Sat),
			single_use: Some(true),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Coffee payment".to_string()),
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().unwrap();

		assert_eq!(expected_encoded, encoded);
	}

	#[test]
	fn test_http_post_transport_kind_1() {
		let expected_encoded = "CREQB1QYQQJ6R5W3C97AR9WD6QYQQGQQQQQQQQQQQ05QCQQYQQ2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MG8QPQSZQQPQYPQQGNGW368QUE69UHKZURF9EJHSCTDWPKX2TNRDAKJ7A339ACXZ7TDV4H8GQCQZ5RXXATNW3HK6PNKV9K82EF3QEMXZMR4V5EQ9X3SJM";

		let transport = Transport {
			kind: TransportType::HttpPost,
			target: "https://api.example.com/v1/payment".to_string(),
			tags: vec![
				TagTuple::new("custom", vec!["value1".to_string(), "value2".to_string()]).unwrap()
			],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("http_test".to_string()),
			amount: Some(250),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode and verify round-trip
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		// Verify transport type is HTTP POST
		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::HttpPost);
		assert_eq!(decoded.transports[0].target, "https://api.example.com/v1/payment");

		// Verify custom tags are preserved
		let mut tags_iter = decoded.transports[0].tags.iter();
		assert!(tags_iter.any(|t| t.key == "custom"
			&& t.values.len() >= 2
			&& t.values[0] == "value1"
			&& t.values[1] == "value2"));
	}

	#[test]
	fn test_relay_tag_extraction_from_nprofile() {
		let expected_encoded = "CREQB1QYQQ5UN9D3SHJHM5V4EHGQSQPQQQQQQQQQQQQEQRQQQSQPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDQUQGZQGQQYQQYQPQ80CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7F39EJHSCTDWPKX2TNRDAKSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7FJ9EJHSCTDWPKX2TNRDAKSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7FN9EJHSCTDWPKX2TNRDAKSKRFDAR";

		let transport = Transport {
			kind: TransportType::Nostr,
			target: "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gprpmhxue69uhhyetvv9unztn90psk6urvv5hxxmmdqyv8wumn8ghj7un9d3shjv3wv4uxzmtsd3jjucm0d5q3samnwvaz7tmjv4kxz7fn9ejhsctdwpkx2tnrdaksxzjpjp".to_string(),
			tags: Vec::new(),
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("relay_test".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode and verify round-trip
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		// Verify relays were extracted and converted to a single "relay" tag
		let nostr_relays = decoded.transports[0].nostr_relays().unwrap();
		assert_eq!(nostr_relays.len(), 3);

		// Verify the nprofile is preserved (relays are encoded back into it)
		assert_eq!(
			"nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gprpmhxue69uhhyetvv9unztn90psk6urvv5hxxmmdqyv8wumn8ghj7un9d3shjv3wv4uxzmtsd3jjucm0d5q3samnwvaz7tmjv4kxz7fn9ejhsctdwpkx2tnrdaksxzjpjp",
			decoded.transports[0].target
		);
	}

	#[test]
	fn test_multiple_transports() {
		let expected_encoded = "CREQB1QYQQ7MT4D36XJHM5WFSKUUMSDAE8GQSQPQQQQQQQQQQQRAQRQQQSQPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDQCQZQ5RP09KK2MN5YPMKJARGYPKH2MR5D9CXCEFQW3EXZMNNWPHHYARNQUQZ7QGQQYQQYQPQ80CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSXQQ9Q9HQYVFHQUQZWQGQQYQSYQPQDP68GURN8GHJ7CTSDYCJUETCV9KHQMR99E3K7MF0WPSHJMT9DE6QWQP6QYQQZQGZQQSXSAR5WPEN5TE0V9CXJV3WV4UXZMTSD3JJUCM0D5HHQCTED4JKUAQRQQGQSURJD9HHY6T50YRXYCTRDD6HQTSH7TP";

		let t1 = Transport {
			kind: TransportType::Nostr,
			target: "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q"
				.to_string(),
			tags: vec![TagTuple::single("n", "17").unwrap()],
		};
		let t2 = Transport {
			kind: TransportType::HttpPost,
			target: "https://api1.example.com/payment".to_string(),
			tags: Vec::new(),
		};
		let t3 = Transport {
			kind: TransportType::HttpPost,
			target: "https://api2.example.com/payment".to_string(),
			tags: vec![TagTuple::single("priority", "backup").unwrap()],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("multi_transport".to_string()),
			amount: Some(500),
			unit: Some(CurrencyUnit::Sat),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("Payment with multiple transports".to_string()),
			single_use: None,
			transports: vec![t1, t2, t3],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode from the encoded string
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		// Verify all three transports are preserved in order
		assert_eq!(decoded.transports.len(), 3);

		// First transport: Nostr
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);
		assert!(decoded.transports[0].target.starts_with("nprofile"));

		// Second transport: HTTP POST
		assert_eq!(decoded.transports[1].kind, TransportType::HttpPost);
		assert_eq!(decoded.transports[1].target, "https://api1.example.com/payment");

		// Third transport: HTTP POST with tags
		assert_eq!(decoded.transports[2].kind, TransportType::HttpPost);
		assert_eq!(decoded.transports[2].target, "https://api2.example.com/payment");
		let mut tags_iter = decoded.transports[2].tags.iter();
		assert!(tags_iter
			.any(|t| t.key == "priority" && t.values.first().map(|s| s.as_str()) == Some("backup")));
	}

	#[test]
	fn test_minimal_transport_nostr_only_pubkey() {
		let expected_encoded = "CREQB1QYQQ6MTFDE5K6CTVTAHX7UM5WGPSQQGQQ5QPS6R5W3C8XW309AKKJMN59EJHSCTDWPKX2TNRDAKSWQP8QYQQZQQZQQSRHUXX8L9EX335Q7HE0F09AEJ04ZPAZPL0NE2CGUKYAWD24MAYT8G7QNXMQ";

		let transport = Transport {
			kind: TransportType::Nostr,
			target: "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q"
				.to_string(),
			tags: Vec::new(),
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("minimal_nostr".to_string()),
			unit: Some(CurrencyUnit::Sat),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			amount: None,
			description: None,
			single_use: None,
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode from the encoded string
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::Nostr);
		assert!(decoded.transports[0].target.starts_with("nprofile"));

		// Tags should be empty for minimal transport
		assert!(decoded.transports[0].tags.is_empty());
	}

	#[test]
	fn test_minimal_transport_http_just_url() {
		let expected_encoded = "CREQB1QYQQCMTFDE5K6CTVTA58GARSQVQQZQQ9QQVXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RSQ8SPQQQSZQSQZA58GARSWVAZ7TMPWP5JUETCV9KHQMR99E3K7MG0TWYGX";

		let transport = Transport {
			kind: TransportType::HttpPost,
			target: "https://api.example.com".to_string(),
			tags: Vec::new(),
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("minimal_http".to_string()),
			unit: Some(CurrencyUnit::Sat),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			amount: None,
			description: None,
			single_use: None,
			transports: vec![transport],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode and verify round-trip
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.transports.len(), 1);
		assert_eq!(decoded.transports[0].kind, TransportType::HttpPost);
		assert_eq!(decoded.transports[0].target, "https://api.example.com");
		assert!(decoded.transports[0].tags.is_empty());
	}

	#[test]
	fn test_nut10_htlc_kind_1() {
		let expected_encoded = "CREQB1QYQQJ6R5D3347AR9WD6QYQQGQQQQQQQQQQP7SQCQQYQQ2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MGXQQF5S4ZVGVSXCMMRDDJKGGRSV9UK6ETWWSYQPTGPQQQSZQSQGFS46VR9XCMRSV3SVFNXYDP3XGERZVNRVCMKZC3NV3JKYVP5X5UKXEFJ8QEXZVTZXQ6XVERPXUMX2CFKXQERVCFKXAJNGVTPV5ERVE3NV33SXQQ5PPKX7CMTW35K6EG2XYMNQVPSXQCRQVPSQVQY5PNJV4N82MNYGGCRXVEJ8QCKXVEHXCMNWETPXGMNXETZXUCNSVMZXUURXVPKXANR2V35XSUNXVM9VCMNSEPCVVEKVVF4VGCKZDEHVD3RYDPKXQUNJCEJXEJS4EHJHC";

		let nut10 = Nut10SecretRequest {
			kind: Kind::HTLC,
			data: "a]0e66820bfb412212cf7ab3deb0459ce282a1b04fda76ea6026a67e41ae26f3dc".to_string(),
			tags: vec![
				TagTuple::single("locktime", "1700000000").unwrap(),
				TagTuple::single(
					"refund",
					"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e",
				)
				.unwrap(),
			],
		};

		let payment_request = CashuPaymentRequest {
			payment_id: Some("htlc_test".to_string()),
			amount: Some(1000),
			unit: Some(CurrencyUnit::Sat),
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: Some("HTLC locked payment".to_string()),
			single_use: None,
			transports: vec![],
			nut10: Some(nut10),
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		// Verify exact encoding matches expected
		assert_eq!(encoded, expected_encoded);

		// Decode from the encoded string and verify round-trip
		let decoded = CashuPaymentRequest::from_bech32_string(&expected_encoded)
			.expect("decoding should work");

		// Verify all top-level fields
		assert_eq!(decoded.payment_id, Some("htlc_test".to_string()));
		assert_eq!(decoded.amount, Some(1000));
		assert_eq!(decoded.unit, Some(CurrencyUnit::Sat));
		assert_eq!(decoded.mints, Some(vec!["https://mint.example.com".to_string()]));
		assert_eq!(decoded.description, Some("HTLC locked payment".to_string()));

		// Verify NUT-10 fields
		let nut10 = decoded.nut10.as_ref().unwrap();
		assert_eq!(nut10.kind, Kind::HTLC);
		assert_eq!(
			nut10.data,
			"a]0e66820bfb412212cf7ab3deb0459ce282a1b04fda76ea6026a67e41ae26f3dc"
		);

		// Verify all tags with exact values
		let tags = &nut10.tags;
		assert_eq!(tags.len(), 2);
		assert_eq!(tags[0], TagTuple::single("locktime", "1700000000").unwrap());
		assert_eq!(
			tags[1],
			TagTuple::single(
				"refund",
				"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e"
			)
			.unwrap()
		);
	}

	#[test]
	fn test_case_insensitive_decoding() {
		let payment_request = CashuPaymentRequest {
			payment_id: Some("case_test".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::Sat),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let uppercase = payment_request.to_bech32_string().expect("encoding should work");

		// Convert to lowercase
		let lowercase = uppercase.to_lowercase();

		// Both uppercase and lowercase should decode successfully
		let decoded_upper =
			CashuPaymentRequest::from_bech32_string(&uppercase).expect("uppercase should decode");
		let decoded_lower =
			CashuPaymentRequest::from_bech32_string(&lowercase).expect("lowercase should decode");

		// Both should produce the same result
		assert_eq!(decoded_upper.payment_id, Some("case_test".to_string()));
		assert_eq!(decoded_lower.payment_id, Some("case_test".to_string()));

		assert_eq!(decoded_upper.amount, decoded_lower.amount);
		assert_eq!(decoded_upper.unit, decoded_lower.unit);
	}

	#[test]
	fn test_custom_currency_unit() {
		let expected_encoded = "CREQB1QYQQKCM4WD6X7M2LW4HXJAQZQQYQQQQQQQQQQQRYQVQQXCN5VVZSQXRGW368QUE69UHK66TWWSHX27RPD4CXCEFWVDHK6PZHCW8";

		let payment_request = CashuPaymentRequest {
			payment_id: Some("custom_unit".to_string()),
			amount: Some(100),
			unit: Some(CurrencyUnit::custom("btc")),
			single_use: None,
			mints: Some(vec!["https://mint.example.com".to_string()]),
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");

		assert_eq!(encoded, expected_encoded);

		// Decode from the expected encoded string
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.unit, Some(CurrencyUnit::custom("btc")));
		assert_eq!(decoded.payment_id, Some("custom_unit".to_string()));
	}

	#[test]
	fn test_custom_currency_unit_long() {
		// Test a unit string longer than 23 bytes to exercise heap allocation
		let long_unit = "this_is_a_very_long_unit_name";

		let payment_request = CashuPaymentRequest {
			payment_id: None,
			amount: Some(100),
			unit: Some(CurrencyUnit::custom(long_unit)),
			single_use: None,
			mints: None,
			description: None,
			transports: vec![],
			nut10: None,
		};

		let encoded = payment_request.to_bech32_string().expect("encoding should work");
		let decoded =
			CashuPaymentRequest::from_bech32_string(&encoded).expect("decoding should work");

		assert_eq!(decoded.unit, Some(CurrencyUnit::custom(long_unit)));
		assert_eq!(decoded.amount, Some(100));
	}

	#[test]
	fn test_transport_tlv_ordering_target_before_kind() {
		// TLV fields should be order-independent. This test verifies that
		// target (0x02) can appear before kind (0x01) and still decode correctly.

		// Test 1: Nostr transport with target before kind
		let pubkey = [0x42u8; 32]; // 32-byte x-only pubkey
		let mut writer = TlvWriter::with_capacity(64);
		writer.write_tlv(0x02, &pubkey); // Target first
		writer.write_tlv(0x01, &[0x00]); // Kind Nostr second
		let bytes = writer.into_bytes();

		let transport = CashuPaymentRequest::decode_transport(&bytes)
			.expect("should decode transport with target before kind");
		assert_eq!(transport.kind, TransportType::Nostr);
		// Target should be encoded as nprofile (even with no relays)
		assert!(transport.target.starts_with("nprofile"));

		// Test 2: HTTP transport with target before kind
		let url = b"https://example.com/callback";
		let mut writer = TlvWriter::with_capacity(64);
		writer.write_tlv(0x02, url); // Target first
		writer.write_tlv(0x01, &[0x01]); // Kind HTTP second
		let bytes = writer.into_bytes();

		let transport = CashuPaymentRequest::decode_transport(&bytes)
			.expect("should decode HTTP transport with target before kind");
		assert_eq!(transport.kind, TransportType::HttpPost);
		assert_eq!(transport.target, "https://example.com/callback");
	}

	#[test]
	fn test_duplicate_tlv_fields() {
		// 1. Top-level: Duplicate Amount (Tag 0x02)
		let mut writer = TlvWriter::with_capacity(32);
		writer.write_tlv(0x02, &100u64.to_be_bytes());
		writer.write_tlv(0x02, &200u64.to_be_bytes());
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::from_bech32_bytes(&bytes), Err(Error::InvalidStructure));

		// 2. Transport: Duplicate Kind (Tag 0x01)
		let mut writer = TlvWriter::with_capacity(16);
		writer.write_tlv(0x01, &[0x00]); // Nostr
		writer.write_tlv(0x01, &[0x01]); // HTTP
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::decode_transport(&bytes), Err(Error::InvalidStructure));

		// 3. Transport: Duplicate Target (Tag 0x02) for Nostr
		let pubkey = vec![0u8; 32];
		let mut writer = TlvWriter::with_capacity(128);
		writer.write_tlv(0x01, &[0x00]); // Kind Nostr
		writer.write_tlv(0x02, &pubkey);
		writer.write_tlv(0x02, &pubkey);
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::decode_transport(&bytes), Err(Error::InvalidStructure));

		// 4. Transport: Duplicate Target (Tag 0x02) for HTTP
		let mut writer = TlvWriter::with_capacity(64);
		writer.write_tlv(0x01, &[0x01]); // Kind HTTP
		writer.write_tlv(0x02, b"https://example.com");
		writer.write_tlv(0x02, b"https://example.org");
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::decode_transport(&bytes), Err(Error::InvalidStructure));

		// 5. NUT-10: Duplicate Kind (Tag 0x01)
		let mut writer = TlvWriter::with_capacity(16);
		writer.write_tlv(0x01, &[0x00]); // Kind P2PK
		writer.write_tlv(0x01, &[0x01]); // Kind HTLC
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::decode_nut10(&bytes), Err(Error::InvalidStructure));

		// 6. NUT-10: Duplicate Data (Tag 0x02)
		let mut writer = TlvWriter::with_capacity(32);
		writer.write_tlv(0x01, &[0x00]); // Kind P2PK
		writer.write_tlv(0x02, b"data1");
		writer.write_tlv(0x02, b"data2");
		let bytes = writer.into_bytes();
		assert_eq!(CashuPaymentRequest::decode_nut10(&bytes), Err(Error::InvalidStructure));
	}
}
