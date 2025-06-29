//! A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
//! resolution directly from untrusted lightning nodes, providing privacy through onion routing.

use std::boxed::Box;
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use lightning::blinded_path::message::{DNSResolverContext, MessageContext};
use lightning::ln::channelmanager::PaymentId;
use lightning::onion_message::dns_resolution::{
	DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery, OMNameResolver,
};
use lightning::onion_message::messenger::{
	Destination, MessageSendInstructions, Responder, ResponseInstruction,
};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::EntropySource;
use lightning::util::logger::Logger;

use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};
use crate::Amount;

struct OsRng;
impl EntropySource for OsRng {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut res = [0; 32];
		getrandom::fill(&mut res).expect("Fetching system randomness should always succeed");
		res
	}
}

struct ChannelState {
	waker: Option<Waker>,
	result: Option<HrnResolution>,
}

struct ChannelSend(Arc<Mutex<ChannelState>>);

impl ChannelSend {
	fn complete(self, result: HrnResolution) {
		let mut state = self.0.lock().unwrap();
		state.result = Some(result);
		if let Some(waker) = state.waker.take() {
			waker.wake();
		}
	}

	fn receiver_alive(&self) -> bool {
		Arc::strong_count(&self.0) > 1
	}
}

struct ChannelRecv(Arc<Mutex<ChannelState>>);

impl Future for ChannelRecv {
	type Output = HrnResolution;
	fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<HrnResolution> {
		let mut state = self.0.lock().unwrap();
		if let Some(res) = state.result.take() {
			state.waker = None;
			Poll::Ready(res)
		} else {
			state.waker = Some(context.waker().clone());
			Poll::Pending
		}
	}
}

fn channel() -> (ChannelSend, ChannelRecv) {
	let state = Arc::new(Mutex::new(ChannelState { waker: None, result: None }));
	(ChannelSend(Arc::clone(&state)), ChannelRecv(state))
}

/// A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
/// resolution directly from untrusted lightning nodes, providing privacy through onion routing.
///
/// This implements LDK's [`DNSResolverMessageHandler`], which it uses to send onion messages (you
/// should make sure to call LDK's [`PeerManager::process_events`] after a query begins) and
/// process response messages.
///
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
pub struct LDKOnionMessageDNSSECHrnResolver<N: Deref<Target = NetworkGraph<L>>, L: Deref>
where
	L::Target: Logger,
{
	network_graph: N,
	resolver: OMNameResolver,
	next_id: AtomicUsize,
	pending_resolutions: Mutex<HashMap<HumanReadableName, Vec<(PaymentId, ChannelSend)>>>,
	message_queue: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	/// Constructs a new [`LDKOnionMessageDNSSECHrnResolver`].
	///
	/// See the struct-level documentation for more info.
	pub fn new(network_graph: N) -> Self {
		Self {
			network_graph,
			next_id: AtomicUsize::new(0),
			// TODO: Swap for `new_without_expiry_validation` when we upgrade to LDK 0.2
			resolver: OMNameResolver::new(0, 0),
			pending_resolutions: Mutex::new(HashMap::new()),
			message_queue: Mutex::new(Vec::new()),
		}
	}

	fn init_resolve_hrn<'a>(
		&'a self, hrn: &HumanReadableName,
	) -> Result<ChannelRecv, &'static str> {
		#[cfg(feature = "std")]
		{
			use std::time::SystemTime;
			let clock_err =
				"DNSSEC validation relies on having a correct system clock. It is currently set before 1970.";
			let now =
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|_| clock_err)?;
			// Use `now / 60` as the block height to expire pending requests after 1-2 minutes.
			self.resolver.new_best_block((now.as_secs() / 60) as u32, now.as_secs() as u32);
		}

		let mut dns_resolvers = Vec::new();
		for (node_id, node) in self.network_graph.read_only().nodes().unordered_iter() {
			if let Some(info) = &node.announcement_info {
				// Sadly, 31 nodes currently squat on the DNS Resolver feature bit
				// without speaking it.
				// Its unclear why they're doing so, but none of them currently
				// also have the onion messaging feature bit set, so here we check
				// for both.
				let supports_dns = info.features().supports_dns_resolution();
				let supports_om = info.features().supports_onion_messages();
				if supports_dns && supports_om {
					if let Ok(pubkey) = node_id.as_pubkey() {
						dns_resolvers.push(Destination::Node(pubkey));
					}
				}
			}
			if dns_resolvers.len() > 5 {
				break;
			}
		}
		if dns_resolvers.is_empty() {
			return Err(
				"Failed to find any DNS resolving nodes, check your network graph is synced",
			);
		}

		let counter = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
		let mut payment_id = [0; 32];
		payment_id[..8].copy_from_slice(&counter.to_ne_bytes());
		let payment_id = PaymentId(payment_id);

		let err = "The provided HRN did not fit in a DNS request";
		// TODO: Once LDK 0.2 ships with a new context authentication method, we shouldn't need the
		// RNG here and can stop depending on std.
		let (query, dns_context) =
			self.resolver.resolve_name(payment_id, hrn.clone(), &OsRng).map_err(|_| err)?;
		let context = MessageContext::DNSResolver(dns_context);

		let mut queue = self.message_queue.lock().unwrap();
		for destination in dns_resolvers {
			let instructions =
				MessageSendInstructions::WithReplyPath { destination, context: context.clone() };
			queue.push((DNSResolverMessage::DNSSECQuery(query.clone()), instructions));
		}

		let (send, recv) = channel();
		let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
		let senders = pending_resolutions.entry(hrn.clone()).or_insert_with(Vec::new);
		senders.push((payment_id, send));

		// If we're running in no-std, we won't expire lookups with the time updates above, so walk
		// the pending resolution list and expire them here.
		pending_resolutions.retain(|_name, resolutions| {
			resolutions.retain(|(_payment_id, resolution)| {
				if !resolution.receiver_alive() {
					// TODO: Once LDK 0.2 ships, expire the pending resolution in the resolver:
					// self.resolver.expire_pending_resolution(name, payment_id);
					false
				} else {
					true
				}
			});
			!resolutions.is_empty()
		});

		Ok(recv)
	}
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> DNSResolverMessageHandler
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn handle_dnssec_query(
		&self, _: DNSSECQuery, _: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		None
	}

	fn handle_dnssec_proof(&self, msg: DNSSECProof, context: DNSResolverContext) {
		let results = self.resolver.handle_dnssec_proof_for_uri(msg.clone(), context);
		if let Some((resolved, res)) = results {
			let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
			for (name, _payment_id) in resolved {
				if let Some(requests) = pending_resolutions.remove(&name) {
					for (_id, send) in requests {
						send.complete(HrnResolution::DNSSEC {
							proof: Some(msg.proof.clone()),
							result: res.clone(),
						});
					}
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		std::mem::take(&mut self.message_queue.lock().unwrap())
	}
}

impl<N: Deref<Target = NetworkGraph<L>> + Sync, L: Deref> HrnResolver
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		match self.init_resolve_hrn(hrn) {
			Err(e) => Box::pin(async move { Err(e) }),
			Ok(recv) => Box::pin(async move { Ok(recv.await) }),
		}
	}

	fn resolve_lnurl<'a>(&'a self, _: String, _: Amount, _: [u8; 32]) -> LNURLResolutionFuture<'a> {
		let err = "resolve_lnurl shouldn't be called when we don't resolve LNURL";
		debug_assert!(false, "{}", err);
		Box::pin(async move { Err(err) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	use std::net::ToSocketAddrs;

	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::PublicKey;

	use lightning::blinded_path::NodeIdLookUp;
	use lightning::ln::peer_handler::{
		ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
	};
	use lightning::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
	use lightning::routing::gossip::{NodeId, P2PGossipSync};
	use lightning::routing::utxo::UtxoLookup;
	use lightning::sign::KeysManager;
	use lightning::util::logger::Record;

	struct TestLogger;
	impl Logger for TestLogger {
		fn log(&self, r: Record) {
			eprintln!("{}", r.args);
		}
	}

	struct NoPeers;
	impl NodeIdLookUp for NoPeers {
		fn next_node_id(&self, _scid: u64) -> Option<PublicKey> {
			None
		}
	}

	#[tokio::test]
	async fn test_dns_om_hrn_resolver() {
		let graph = Arc::new(NetworkGraph::new(Network::Bitcoin, &TestLogger));
		let resolver = Arc::new(LDKOnionMessageDNSSECHrnResolver::new(Arc::clone(&graph)));
		let signer = Arc::new(KeysManager::new(&OsRng.get_secure_random_bytes(), 0, 0));
		let message_router = Arc::new(DefaultMessageRouter::new(Arc::clone(&graph), &OsRng));
		let messenger = Arc::new(OnionMessenger::new(
			&OsRng,
			Arc::clone(&signer),
			&TestLogger,
			&NoPeers,
			message_router,
			&IgnoringMessageHandler {},
			&IgnoringMessageHandler {},
			Arc::clone(&resolver),
			&IgnoringMessageHandler {},
		));
		let no_utxos = None::<&(dyn UtxoLookup + Sync + Send)>;
		let handlers = MessageHandler {
			chan_handler: Arc::new(ErroringMessageHandler::new()),
			route_handler: Arc::new(P2PGossipSync::new(Arc::clone(&graph), no_utxos, &TestLogger)),
			onion_message_handler: Arc::clone(&messenger),
			custom_message_handler: &IgnoringMessageHandler {},
		};
		let rand = OsRng.get_secure_random_bytes();
		let peer_manager =
			Arc::new(PeerManager::new(handlers, 0, &rand, &TestLogger, Arc::clone(&signer)));

		// Connect to a static LDK node which we know will do DNS resolutions for us.
		let their_id_hex = "03db10aa09ff04d3568b0621750794063df401e6853c79a21a83e1a3f3b5bfb0c8";
		let their_id = PublicKey::from_slice(&Vec::<u8>::from_hex(their_id_hex).unwrap()).unwrap();
		let addr = "ldk-ln-node.bitcoin.ninja:9735".to_socket_addrs().unwrap().next().unwrap();
		let _ = lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), their_id, addr)
			.await
			.unwrap();

		let pm_reference = Arc::clone(&peer_manager);
		tokio::spawn(async move {
			pm_reference.process_events();
			tokio::time::sleep(Duration::from_micros(10)).await;
		});

		let their_node_id = NodeId::from_pubkey(&their_id);
		loop {
			{
				let graph = graph.read_only();
				let have_announcement =
					graph.nodes().get(&their_node_id).map(|node| node.announcement_info.is_some());
				if have_announcement.unwrap_or(false) {
					break;
				}
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
			peer_manager.process_events();
		}

		let instructions = PaymentInstructions::parse(
			"send.some@satsto.me",
			bitcoin::Network::Bitcoin,
			&*resolver,
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

			instr.set_amount(Amount::from_sats(100_000).unwrap(), &*resolver).await.unwrap()
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
