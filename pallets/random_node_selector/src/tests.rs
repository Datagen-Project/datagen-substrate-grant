use crate::mock::*;
use frame_support::assert_ok;
use sp_core::OpaquePeerId;

/// Test the random hash generator.
#[test]
fn create_random_hash() {
	new_test_ext().execute_with(|| {

		// Create random hash.
		assert_ok!(RandomNodeSelector::create_random_hash(Origin::signed(1)));
	})
}


/// Test the random number generator.
#[test]
fn create_random_number() {
	new_test_ext().execute_with(|| {

		// Create random number.
		assert_ok!(RandomNodeSelector::create_random_number(Origin::signed(1)));
	});
}

/// Test add owner.
#[test]
fn check_add_owner() {
	new_test_ext().execute_with(|| {

		// Add owner.
		assert_ok!(RandomNodeSelector::add_owner(Origin::signed(1), 1, OpaquePeerId(vec![1, 2, 3, 4])));
	});
}

/// Test remove owner.
#[test]
fn check_remove_owner() {
	new_test_ext().execute_with(|| {

		// Remove owner.
		assert_ok!(RandomNodeSelector::remove_owner(Origin::signed(1), 1));
	})
}

/// Check Genesis Config and get_owner_list function.
#[test]
fn check_initial_owners_list() {
	new_test_ext().execute_with(|| {

		// Dispatch a signed extrinsic.
		assert_ok!(RandomNodeSelector::get_owners_list(Origin::signed(1)));
		run_to_block(1);
		System::assert_last_event(Event::RandomNodeSelector(crate::Event::OwnersList {
			owners: vec![
				(1, OpaquePeerId(vec![1, 2, 3, 4])),
				(2, OpaquePeerId(vec![1, 2, 3, 4])),
			],
		}));
	});
}


/// Check total_elements function.
#[test]
fn check_total_items_in_map() {
	new_test_ext().execute_with(|| {

		// Dispatch a signed extrinsic.
		assert_ok!(RandomNodeSelector::add_owner(Origin::signed(1), 3, OpaquePeerId(vec![1, 2, 3, 4])));
		run_to_block(1);
		assert_ok!(RandomNodeSelector::total_elements(Origin::signed(1)));
		System::assert_last_event(crate::Event::TotalItemsInMap(3).into());
	});
}



