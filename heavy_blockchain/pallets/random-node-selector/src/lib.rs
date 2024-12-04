#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Encode, Decode};
use frame_support::traits::Randomness;
use scale_info::prelude::vec::Vec;
pub use pallet::*;
use sp_core::OpaquePeerId as PeerId;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::{pallet_prelude::*};
	use frame_support::traits::Randomness;
	use scale_info::prelude::vec::Vec;
	use sp_core::OpaquePeerId as PeerId;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type Randomness: Randomness<Self::Hash, BlockNumberFor<Self>>;
	}

	// Events of the pallet.

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {

		/// Last random hash.
		RandomHash { hash: T::Hash },

		/// Last random number.
		RandomNumber { number: u32 },

		/// Node has been taken.
		SetOwnerReliableNode {
			owner: T::AccountId,
			peer_id: PeerId,
		},

		/// Node has been removed.
		RemoveReliableNode {
			owner: T::AccountId,
			peer_id: PeerId,
		},

		/// The node and its owner to check + random number used to select the owner.
		ReliableNodeToCheck {
			owner: T::AccountId,
			peer_id: PeerId,
			random_number: u32,
		},

		/// Controllers and which will check the selected node.
		Controllers {
			controller_1_account_id: T::AccountId,
			controller_1_peer_id: PeerId,
			random_number_1: u32,
			controller_2_account_id: T::AccountId,
			controller_2_peer_id: PeerId,
			random_number_2: u32,
			controller_3_account_id: T::AccountId,
			controller_3_peer_id: PeerId,
			random_number_3: u32,
		},

		/// An array with all node owners.
		/// [Node ReliableNode, Node PeerId]
		ReliableNodeList {
			owners: Vec<(PeerId, T::AccountId)>,
		},

		/// Number of elements in the map.
		TotalItemsInMap {
			total_items: u32,
		}
	}

	// Errors inform users that something went wrong.

	#[pallet::error]
	pub enum Error<T> {
		/// No node to check.
		NoReliableNodeToCheck,

		/// The node is already taken.
		AlreadyTakenNode,

		/// You are not the owner of this node.
		NotOwner,
	}

	// Storage for the pallet.

	/// The las random hash.
	/// Dev - This is only for testing purposes.
	#[pallet::storage]
	pub(super) type RandomHash<T: Config> =
		StorageValue<_, T::Hash>;


	/// The last owner to check.
	#[pallet::storage]
	#[pallet::getter(fn reliable_node_to_check)]
	pub(super) type ReliableNodeToCheck<T: Config> =
		StorageValue<_, (PeerId, T::AccountId)>;

	/// The last random number.
	#[pallet::storage]
	#[pallet::getter(fn random_number)]
	pub(super) type RandomNumber<T: Config> =
		StorageValue<_, u32, ValueQuery>;


	/// Nonce for generating random number.
	#[pallet::storage]
	#[pallet::getter(fn get_nonce)]
	pub(super) type Nonce<T: Config> = StorageValue<
		_,
		u64,
		ValueQuery
		>;

	/// A map that maintains the ownership of each node.
	/// [Node Owner, Node PeerId]
	#[pallet::storage]
	#[pallet::getter(fn reliable_node)]
	pub type ReliableNode<T: Config> = CountedStorageMap<
		_,
		Blake2_128Concat,
		PeerId,
		T::AccountId
		>;

	// Genesis config for the random node selector pallet.
	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_node_owners: Vec<(PeerId, T::AccountId)>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			for (peer_id, owner) in &self.initial_node_owners {
				<ReliableNode<T>>::insert(peer_id, owner);
			}
		}
	}

	// Dispatchable functions allow users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {

		// Test functions.

		/// Create a new random hash.
		/// Dev - This function is only for testing purposes.
		#[pallet::call_index(0)]
		#[pallet::weight({100})]
		pub fn test_create_random_hash(
			origin: OriginFor<T>
		) -> DispatchResult {
			// Account calling this dispatchable.
			let _sender = ensure_signed(origin)?;
				// Random value.
				let nonce = Self::get_and_increment_nonce();
				let (random_value, _) = T::Randomness::random(&nonce);
			// Write the random value to storage.
			<RandomHash<T>>::put(random_value);
			Self::deposit_event(Event::RandomHash{hash: random_value});

			Ok(())
		}

		/// Crate a new random number.
		/// Dev - This function is only for testing purposes.
		#[pallet::call_index(1)]
		#[pallet::weight({100})]
		pub fn test_create_random_number(
			origin: OriginFor<T>
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;

			let random_number = Self::generate_random_number();

			<RandomNumber<T>>::put(random_number);
			Self::deposit_event(Event::RandomNumber { number: random_number });

			Ok(())
		}

		/// Number of elements in the map.
		/// Dev - This function is only for testing purposes.
		#[pallet::call_index(2)]
		#[pallet::weight({100})]
		pub fn test_total_elements(
			origin: OriginFor<T>
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;

			// Count how many owners are in the list.
			let total = <ReliableNode<T>>::count();

			Self::deposit_event(Event::TotalItemsInMap{total_items: total});

			Ok(())
		}


		/// Get the list of all node owners.
		/// Dev - This function is only for development purposes.
		#[pallet::call_index(3)]
		#[pallet::weight({100})]
		pub fn test_get_owners_list(
			origin: OriginFor<T>
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			// Get all owners.
			let owners = <ReliableNode<T>>::iter().collect::<Vec<_>>();
			Self::deposit_event(Event::ReliableNodeList {
				owners,
			});
			Ok(())
		}

		/// Generate a random number within a range.
		/// Dev - This function is only for demonstration purposes.
		#[pallet::call_index(4)]
		#[pallet::weight({100})]
		pub fn test_generate_random_number_range(
			origin: OriginFor<T>,
			max: u32
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;

			let random_number = Self::generate_random_number_in_range(max);

			Self::deposit_event(Event::RandomNumber { number: random_number });

			Ok(())
		}


		// Production functions.

		/// Update a reliable node list.
		/// Add a reliable node to the list and set the ownership.
		#[pallet::call_index(5)]
		#[pallet::weight({100})]
		pub fn add_reliable_node(
			origin: OriginFor<T>,
			owner: T::AccountId,
			peer_id: PeerId
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			ensure!(!<ReliableNode<T>>::contains_key(&peer_id), Error::<T>::AlreadyTakenNode);
			// Add the owner to the list of owners.
			<ReliableNode<T>>::insert(&peer_id, &owner);
			Self::deposit_event(Event::SetOwnerReliableNode {
				peer_id,
				owner,
			});
			Ok(())
		}

		/// Update reliable node list.
		/// Remove a reliable node.
		#[pallet::call_index(6)]
		#[pallet::weight({100})]
		pub fn remove_reliable_node(
			origin: OriginFor<T>,
			peer_id: PeerId
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;
			ensure!(<ReliableNode<T>>::contains_key(&peer_id), Error::<T>::NoReliableNodeToCheck);
			ensure!(_sender == <ReliableNode<T>>::get(&peer_id).unwrap(), Error::<T>::NotOwner);
			// Remove the owner from the list of owners.
			<ReliableNode<T>>::remove(&peer_id);
			Self::deposit_event(Event::RemoveReliableNode {
				owner: _sender,
				peer_id,
			});
			Ok(())
		}

		/// Select a random reliable node from the list for the control.
		/// Emit the selected node and the random number.
		#[pallet::call_index(7)]
		#[pallet::weight({100})]
		pub fn random_node_to_check(
			origin: OriginFor<T>
		) -> DispatchResult {
			let _sender = ensure_signed(origin)?;

			let (selected_owner_to_unwrap, random_number) = Self::select_random_node();

			let selected_owner = selected_owner_to_unwrap.unwrap();

			<ReliableNodeToCheck<T>>::put(selected_owner.clone());
			<RandomNumber<T>>::put(random_number);

			Self::deposit_event(Event::ReliableNodeToCheck {
				owner: selected_owner.1,
				peer_id: selected_owner.0,
				random_number,
			});

			Ok(())
		}

		/// Select three random reliable nodes from the list as controllers.
		/// Emit the selected controller nodes and the random numbers.
		#[pallet::call_index(8)]
		#[pallet::weight({100})]
		pub fn random_checker_node_selector(
			origin: OriginFor<T>
		)-> DispatchResult {
			let _sender = ensure_signed(origin)?;

			// Check if the reliable node to check has been chosen.
			ensure!(<ReliableNodeToCheck<T>>::exists(), Error::<T>::NoReliableNodeToCheck);

			let mut selected_controller_to_unwrap_1;
			let mut selected_controller_to_unwrap_2;
			let mut selected_controller_to_unwrap_3;

			let mut random_number_1;
			let mut random_number_2;
			let mut random_number_3;

			loop {
				(selected_controller_to_unwrap_1, random_number_1) = Self::select_random_node();
				if selected_controller_to_unwrap_1 != <ReliableNodeToCheck<T>>::get() {
					break;
				}
			}

			loop {
				(selected_controller_to_unwrap_2, random_number_2) = Self::select_random_node();
				if selected_controller_to_unwrap_1 != selected_controller_to_unwrap_2 && selected_controller_to_unwrap_2 != <ReliableNodeToCheck<T>>::get() {
					break;
				}
			}

			loop {
				(selected_controller_to_unwrap_3, random_number_3) = Self::select_random_node();
				if selected_controller_to_unwrap_1 != selected_controller_to_unwrap_3 && selected_controller_to_unwrap_2 != selected_controller_to_unwrap_3 && selected_controller_to_unwrap_3 != <ReliableNodeToCheck<T>>::get() {
					break;
				}
			}

			let selected_controller_1 = selected_controller_to_unwrap_1.unwrap();
			let selected_controller_2 = selected_controller_to_unwrap_2.unwrap();
			let selected_controller_3 = selected_controller_to_unwrap_3.unwrap();


			Self::deposit_event(Event::Controllers {
				controller_1_account_id: selected_controller_1.1,
				controller_1_peer_id: selected_controller_1.0,
				random_number_1,
				controller_2_account_id: selected_controller_2.1,
				controller_2_peer_id: selected_controller_2.0,
				random_number_2,
				controller_3_account_id: selected_controller_3.1,
				controller_3_peer_id: selected_controller_3.0,
				random_number_3,
			});

			Ok(())
		}

	}
}

impl<T: Config> Pallet<T> {
	/// Progressive nonce to generate random values.
	fn get_and_increment_nonce() -> Vec<u8> {
		let nonce = Nonce::<T>::get();
		Nonce::<T>::put(nonce.wrapping_add(1));
		nonce.encode()
	}

	/// Generate a random number.
	fn generate_random_number() -> u32 {
		let (random_seed, _) = T::Randomness::random(&Self::get_and_increment_nonce());
		let random_number = <u32>::decode(&mut random_seed.as_ref())
			.expect("secure hashes should always be bigger than u32; qed");
		random_number
	}

	/// Select a random owner and his node_id from the list of owners.
	/// Return the selected owner and the random number used to select the owner.
	fn select_random_node() -> (Option<(PeerId, T::AccountId)>, u32) {
		let owners = <ReliableNode<T>>::iter().collect::<Vec<_>>();
		let random_number = Self::generate_random_number_in_range(owners.len() as u32);
		(Some(owners[random_number as usize].clone()), random_number)
	}

	/// Generate a random number within a range 0 to max.
	/// This function is used to generate a random number within a range.
	/// The range is from zero to max.
	fn generate_random_number_in_range(max: u32) -> u32 {
		let random_number = Self::generate_random_number();
		random_number % max
	}
}

