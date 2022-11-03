use bitvec::order::Lsb0;
use bitvec::prelude::BitVec;
use borsh::{BorshDeserialize, BorshSerialize};
use eth2_utility::consensus::{
    compute_domain, compute_signing_root, get_participant_pubkeys, Network, NetworkConfig,
    DOMAIN_SYNC_COMMITTEE, MIN_SYNC_COMMITTEE_PARTICIPANTS,
};
use eth_types::eth2::LightClientUpdate;
use eth_types::eth2::SyncCommittee;
use near_sdk::near_bindgen;
use std::str::FromStr;
use tree_hash::TreeHash;

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct LightClientStruct {
    pub light_client_update: LightClientUpdate,
    pub sync_committee: SyncCommittee,
}

#[near_bindgen]
#[derive(Default, BorshSerialize, BorshDeserialize)]
struct Counter {
    counter: u64,
}

#[near_bindgen]
impl Counter {
    #[init]
    #[payable]
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    #[payable]
    pub fn unprotected(&mut self) {
        self.counter += 1
    }

    pub fn get_counter(&self) -> u64 {
        self.counter
    }

    pub fn verify_bls_signature(&self, #[serializer(borsh)] input: LightClientStruct) -> u64 {
        let ethereum_network = Network::from_str("goerli").unwrap();
        let config = NetworkConfig::new(&ethereum_network);

        let sync_committee_bits = BitVec::<u8, Lsb0>::from_slice(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_bits
                .0,
        );

        let sync_committee_bits_sum: u64 = sync_committee_bits.count_ones().try_into().unwrap();
        if sync_committee_bits_sum < MIN_SYNC_COMMITTEE_PARTICIPANTS {
            return 5;
        }
        if sync_committee_bits_sum * 3 < (sync_committee_bits.len() * 2).try_into().unwrap() {
            return 5;
        }

        let participant_pubkeys =
            get_participant_pubkeys(&input.sync_committee.pubkeys.0, &sync_committee_bits);

        let fork_version = config
            .compute_fork_version_by_slot(input.light_client_update.signature_slot)
            .expect("Unsupported fork");

        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version,
            config.genesis_validators_root.into(),
        );

        let signing_root = compute_signing_root(
            eth_types::H256(
                input
                    .light_client_update
                    .attested_beacon_header
                    .tree_hash_root(),
            ),
            domain,
        );

        let mut pubkeys: Vec<u8> = vec![];
        for pubkey in participant_pubkeys {
            pubkeys.append(&mut pubkey.0.to_vec());
        }

        near_sdk::env::verify_bls12_381(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_signature
                .0,
            &signing_root.0.as_bytes(),
            &pubkeys,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::LightClientStruct;
    use borsh::{BorshDeserialize, BorshSerialize};
    use eth_types::eth2::LightClientUpdate;
    use eth_types::eth2::SyncCommittee;
    use near_sdk::AccountId;
    use serde_json::json;
    use test_utils::*;
    use workspaces::Contract;

    #[derive(Debug, Clone)]
    pub struct ConfigForTests {
        pub path_to_current_sync_committee: String,
        pub path_to_next_sync_committee: String,
        pub path_to_light_client_updates: String,
        pub network_name: String,
    }

    fn get_config() -> ConfigForTests {
        ConfigForTests {
            path_to_current_sync_committee: "./data/next_sync_committee_goerli_period_473.json"
                .to_string(),
            path_to_next_sync_committee: "./data/next_sync_committee_goerli_period_474.json"
                .to_string(),
            path_to_light_client_updates:
                "./data/light_client_updates_goerli_slots_3885697_3886176.json".to_string(),
            network_name: "goerli".to_string(),
        }
    }

    async fn view_method_with_borsh_args(
        contract: &Contract,
        method_name: &str,
        args: Vec<u8>,
    ) -> u64 {
        let res = contract.view(method_name, args).await.unwrap();

        return serde_json::from_slice(&res.result).unwrap();
    }

    const WASM_FILEPATH: &str =
        "./target/wasm32-unknown-unknown/release/bls_signature_example_contract.wasm";

    #[tokio::test]
    async fn base_scenario() {
        let (_, contract) = get_contract(WASM_FILEPATH).await;
        assert!(call!(contract, "new").await);
        assert!(call!(contract, "unprotected").await);
        check_counter(&contract, 1).await;
    }

    #[tokio::test]
    async fn test_verify_bls_signature() {
        let (_, contract) = get_contract(WASM_FILEPATH).await;
        assert!(call!(contract, "new").await);

        let config = get_config();
        let light_client_updates: Vec<LightClientUpdate> = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_light_client_updates)
                .expect("Unable to read file"),
        )
        .unwrap();
        let current_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_current_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();
        let next_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_next_sync_committee.clone())
                .expect("Unable to read file"),
        )
        .unwrap();

        let mut input = LightClientStruct {
            light_client_update: light_client_updates[0].clone(),
            sync_committee: current_sync_committee,
        };

        assert_eq!(
            view_method_with_borsh_args(
                &contract,
                "verify_bls_signature",
                input.try_to_vec().unwrap()
            )
            .await,
            0
        );

        input = LightClientStruct {
            light_client_update: light_client_updates[0].clone(),
            sync_committee: next_sync_committee,
        };

        assert_eq!(
            view_method_with_borsh_args(
                &contract,
                "verify_bls_signature",
                input.try_to_vec().unwrap()
            )
            .await,
            5
        );
    }
}
