#![cfg_attr(not(feature = "std"), no_std)]

// #[cfg(feature = "std")]

use cumulus_pallet_xcm::{ensure_sibling_para, Origin as CumulusOrigin};
use cumulus_primitives_core::ParaId;
use frame_support::{pallet_prelude::*, parameter_types, BoundedVec};
use frame_system::Config as SystemConfig;
pub use pallet::*;
use sp_runtime::traits::Saturating;
use sp_std::{prelude::*, vec};
use staging_xcm as xcm;
use xcm::latest::prelude::*;

parameter_types! {
   const MaxParachains: u32 = 100;
   const MaxPayloadSize: u32 = 1024;
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		type RuntimeOrigin: From<<Self as SystemConfig>::RuntimeOrigin>
			+ Into<Result<CumulusOrigin, <Self as Config>::RuntimeOrigin>>;

		type RuntimeCall: From<Call<Self>> + Encode;

		/// Utility for sending XCM messages.
		type XcmSender: SendXcm;
	}

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub(super) type XcmQueque<T: Config> = StorageValue<
		_,
		BoundedVec<(ParaId, BoundedVec<u8, MaxPayloadSize>), MaxParachains>,
		ValueQuery,
	>;

	#[pallet::storage]
	pub(super) type ReceivedXcm<T: Config> =
		StorageMap<_, Blake2_128Concat, u32, ParaId, ValueQuery>;

	#[pallet::storage]
	pub(super) type Ack<T: Config> =
		StorageMap<_, Blake2_128Concat, u32, (u32, ParaId), ValueQuery>;

	#[pallet::storage]
	pub(super) type MessageCount<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	pub(super) type XcmMessages<T: Config> =
		StorageMap<_, Blake2_128Concat, u32, BlockNumberFor<T>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		ErrorSendingXcmMessage {
			e: SendError,
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
		},
		XcmMessageSent {
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
			hash: XcmHash,
			cost: Assets,
		},
		XcmRecieved {
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
		},
		XcmAckSent {
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
			hash: XcmHash,
			cost: Assets,
		},
		ErrorSendingXcmAck {
			e: SendError,
			para: ParaId,
			seq: u32,
		},

		XcmAckReceived {
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
			block_number: BlockNumberFor<T>,
		},
		UnknwonXcmMessage {
			para: ParaId,
			seq: u32,
			payload: Vec<u8>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		PayloadTooLarge,
		XcmQuequeExceeded,
		TooManyXcmReceived,
		TooManyAck,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_finalize(n: BlockNumberFor<T>) {
			Self::send_xcm_message(n);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn initialze_xcm(
			origin: OriginFor<T>,
			para: ParaId,
			payload: Vec<u8>,
		) -> DispatchResult {
			ensure_root(origin)?;

			let payload = BoundedVec::<u8, MaxPayloadSize>::try_from(payload)
				.map_err(|_| Error::<T>::PayloadTooLarge)?;

			XcmQueque::<T>::try_mutate(|t| {
				t.try_push((para, payload)).map_err(|_| Error::<T>::XcmQuequeExceeded)
			})?;

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight({0})]
		pub fn handle_xcm(origin: OriginFor<T>, seq: u32, payload: Vec<u8>) -> DispatchResult {
			let para = ensure_sibling_para(<T as Config>::RuntimeOrigin::from(origin))?;

			Self::deposit_event(Event::XcmRecieved { para, seq, payload: payload.clone() });

			let _bounded_payload = BoundedVec::<u8, MaxPayloadSize>::try_from(payload.clone())
				.map_err(|_| Error::<T>::PayloadTooLarge)?;

			ReceivedXcm::<T>::insert(seq, para);

			match send_xcm::<T::XcmSender>(
				(Parent, Junction::Parachain(para.into())).into(),
				Xcm(vec![Transact {
					origin_kind: OriginKind::Native,
					require_weight_at_most: xcm::v3::Weight::from_parts(1_000, 1_000),
					call: <T as Config>::RuntimeCall::from(Call::<T>::handle_xcm_ack {
						seq,
						payload: payload.clone(),
					})
					.encode()
					.into(),
				}]),
			) {
				Ok((hash, cost)) =>
					Self::deposit_event(Event::XcmAckSent { para, seq, payload, hash, cost }),
				Err(e) => Self::deposit_event(Event::ErrorSendingXcmAck { e, para, seq }),
			}
			Ok(())
		}

		// pong received
		#[pallet::call_index(2)]
		#[pallet::weight({0})]
		pub fn handle_xcm_ack(origin: OriginFor<T>, seq: u32, payload: Vec<u8>) -> DispatchResult {
			let para = ensure_sibling_para(<T as Config>::RuntimeOrigin::from(origin))?;

			if let Some(sent_at) = XcmMessages::<T>::take(seq) {
				Ack::<T>::insert(seq, (seq, para));

				Self::deposit_event(Event::XcmAckReceived {
					para,
					seq,
					payload,
					block_number: frame_system::Pallet::<T>::block_number().saturating_sub(sent_at),
				});
			} else {
				Self::deposit_event(Event::UnknwonXcmMessage { para, seq, payload })
			}
			Ok(())
		}
	}

	// private functions
	impl<T: Config> Pallet<T> {
		fn send_xcm_message(n: BlockNumberFor<T>) {
			for (para, payload) in XcmQueque::<T>::get().into_iter() {
				let seq = MessageCount::<T>::mutate(|seq| {
					*seq += 1;
					*seq
				});

				match send_xcm::<T::XcmSender>(
					(Parent, Junction::Parachain(para.into())).into(),
					Xcm(vec![Transact {
						origin_kind: OriginKind::Native,
						require_weight_at_most: xcm::v3::Weight::from_parts(1_00, 1_000),
						call: <T as Config>::RuntimeCall::from(Call::<T>::handle_xcm {
							seq,
							payload: payload.clone().to_vec(),
						})
						.encode()
						.into(),
					}]),
				) {
					Ok((hash, cost)) => {
						XcmMessages::<T>::insert(seq, n);
						Self::deposit_event(Event::XcmMessageSent {
							para,
							seq,
							payload: payload.to_vec(),
							hash,
							cost,
						});
					},
					Err(e) => Self::deposit_event(Event::ErrorSendingXcmMessage {
						e,
						para,
						seq,
						payload: payload.to_vec(),
					}),
				}
			}
		}
	}
}
