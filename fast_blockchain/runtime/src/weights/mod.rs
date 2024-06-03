// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Parity Bridges Common.

// Parity Bridges Common is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Bridges Common is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Bridges Common.  If not, see <http://www.gnu.org/licenses/>.

mod pallet_bridge_messages;

use ::pallet_bridge_messages::WeightInfoExt as MessagesWeightInfoExt;
use frame_support::weights::Weight;
use ::pallet_bridge_relayers::WeightInfoExt as _;

impl MessagesWeightInfoExt for pallet_bridge_messages::WeightInfo<crate::Runtime> {
    fn expected_extra_storage_proof_size() -> u32 {
        bp_bridge_hub_rococo::EXTRA_STORAGE_PROOF_SIZE
    }

    fn receive_messages_proof_overhead_from_runtime() -> Weight {
        pallet_bridge_relayers::WeightInfo::receive_messages_proof_overhead_from_runtime(
        )
    }

    fn receive_messages_delivery_proof_overhead_from_runtime() -> Weight {
        pallet_bridge_relayers::WeightInfo::receive_messages_delivery_proof_overhead_from_runtime()
    }
}