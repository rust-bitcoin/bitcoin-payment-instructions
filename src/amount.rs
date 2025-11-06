//! Because lightning uses "milli-satoshis" rather than satoshis for its native currency amount,
//! parsing payment instructions requires amounts with sub-satoshi precision.
//!
//! Thus, here, we define an [`Amount`] type similar to [`bitcoin::Amount`] but with sub-satoshi
//! precision.

use bitcoin::Amount as BitcoinAmount;

use core::fmt;

/// An amount of Bitcoin
///
/// Sadly, because lightning uses "milli-satoshis" we cannot directly use rust-bitcoin's `Amount`
/// type.
///
/// In general, when displaying amounts to the user, you should use [`Self::sats_rounding_up`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(u64);

impl fmt::Debug for Amount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		write!(f, "{} milli-satoshis", self.0)
	}
}

const MAX_MSATS: u64 = 21_000_000_0000_0000_000;

impl Amount {
	/// The maximum possible [`Amount`], equal to 21 million BTC
	pub const MAX: Amount = Amount(MAX_MSATS);

	/// Zero milli-satoshis
	pub const ZERO: Amount = Amount(0);

	/// The amount in milli-satoshis
	#[inline]
	pub const fn milli_sats(&self) -> u64 {
		self.0
	}

	/// The amount in satoshis, if it is exactly a whole number of sats.
	#[inline]
	pub const fn sats(&self) -> Result<u64, ()> {
		if self.0 % 1000 == 0 {
			Ok(self.0 / 1000)
		} else {
			Err(())
		}
	}

	/// The amount in satoshis, rounding up to the next whole satoshi.
	#[inline]
	pub const fn sats_rounding_up(&self) -> u64 {
		(self.0 + 999) / 1000
	}

	/// Constructs a new [`Amount`] for the given number of milli-satoshis.
	///
	/// Fails only if `msats` is greater than 21 million Bitcoin (in milli-satoshis).
	#[inline]
	pub const fn from_milli_sats(msats: u64) -> Result<Self, ()> {
		if msats > MAX_MSATS {
			Err(())
		} else {
			Ok(Amount(msats))
		}
	}

	/// Constructs a new [`Amount`] for the given number of satoshis.
	///
	/// Fails only if `sats` is greater than 21 million Bitcoin (in satoshis).
	#[inline]
	pub const fn from_sats(sats: u64) -> Result<Self, ()> {
		Self::from_milli_sats(sats.saturating_mul(1000))
	}

	/// Constructs a new [`Amount`] for the given number of satoshis, panicking if the amount is
	/// too large.
	pub(crate) const fn from_sats_panicy(sats: u64) -> Self {
		let amt = sats.saturating_mul(1000);
		if amt > MAX_MSATS {
			panic!("Sats value greater than 21 million Bitcoin");
		} else {
			Amount(amt)
		}
	}

	/// Adds an [`Amount`] to this [`Amount`], saturating to avoid overflowing 21 million bitcoin.
	#[inline]
	pub const fn saturating_add(self, rhs: Amount) -> Amount {
		match self.0.checked_add(rhs.0) {
			Some(amt) if amt <= MAX_MSATS => Amount(amt),
			_ => Amount(MAX_MSATS),
		}
	}

	/// Subtracts an [`Amount`] from this [`Amount`], saturating to avoid underflowing.
	#[inline]
	pub const fn saturating_sub(self, rhs: Amount) -> Amount {
		Amount(self.0.saturating_sub(rhs.0))
	}

	/// Returns an object that implements [`core::fmt::Display`] which writes out the amount, in
	/// bitcoin, with a decimal point between the whole-bitcoin and partial-bitcoin amounts, with
	/// any milli-satoshis rounded up to the next whole satoshi.
	#[inline]
	pub fn btc_decimal_rounding_up_to_sats(self) -> FormattedAmount {
		FormattedAmount(self)
	}

	/// Returns the maximum of two amounts.
	#[inline]
	#[must_use]
	pub fn max(&self, other: &Amount) -> Amount {
		Amount(self.0.max(other.0))
	}

	/// Returns the minimum of two amounts.
	#[inline]
	#[must_use]
	pub fn min(&self, other: &Amount) -> Amount {
		Amount(self.0.min(other.0))
	}
}

#[derive(Clone, Copy)]
/// A simple type which wraps an [`Amount`] and formats it according to instructions when it was
/// generated.
pub struct FormattedAmount(Amount);

impl fmt::Display for FormattedAmount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		let total_sats = self.0.sats_rounding_up();
		let btc = total_sats / 1_0000_0000;
		let mut sats = total_sats % 1_0000_0000;
		write!(f, "{}", btc)?;
		if sats != 0 {
			let mut digits = 8;
			while sats % 10 == 0 {
				digits -= 1;
				sats /= 10;
			}
			write!(f, ".{:0digits$}", sats, digits = digits)?;
		}
		Ok(())
	}
}

impl From<BitcoinAmount> for Amount {
	fn from(amt: BitcoinAmount) -> Amount {
		Amount(amt.to_sat() * 1000)
	}
}

#[cfg(test)]
mod test {
	use super::Amount;

	use alloc::string::ToString;

	#[test]
	#[rustfmt::skip]
	fn test_display() {
		assert_eq!(Amount::from_milli_sats(0).unwrap().btc_decimal_rounding_up_to_sats().to_string(),     "0");
		assert_eq!(Amount::from_milli_sats(1).unwrap().btc_decimal_rounding_up_to_sats().to_string(),     "0.00000001");
		assert_eq!(Amount::from_sats(1).unwrap().btc_decimal_rounding_up_to_sats().to_string(),           "0.00000001");
		assert_eq!(Amount::from_sats(10).unwrap().btc_decimal_rounding_up_to_sats().to_string(),          "0.0000001");
		assert_eq!(Amount::from_sats(15).unwrap().btc_decimal_rounding_up_to_sats().to_string(),          "0.00000015");
		assert_eq!(Amount::from_sats(1_0000).unwrap().btc_decimal_rounding_up_to_sats().to_string(),      "0.0001");
		assert_eq!(Amount::from_sats(1_2345).unwrap().btc_decimal_rounding_up_to_sats().to_string(),      "0.00012345");
		assert_eq!(Amount::from_sats(1_2345_6789).unwrap().btc_decimal_rounding_up_to_sats().to_string(), "1.23456789");
		assert_eq!(Amount::from_sats(1_0000_0000).unwrap().btc_decimal_rounding_up_to_sats().to_string(), "1");
		assert_eq!(Amount::from_sats(5_0000_0000).unwrap().btc_decimal_rounding_up_to_sats().to_string(), "5");
	}
}
