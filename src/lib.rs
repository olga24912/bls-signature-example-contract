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
use bls::{AggregatePublicKey, PublicKey};
use tree_hash::TreeHash;

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct LightClientStruct {
    pub light_client_update: LightClientUpdate,
    pub sync_committee: SyncCommittee,
    pub pk_aggregate: Vec<u8>,
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

        near_sdk::env::bls12_381_aggregate_verify(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_signature
                .0,
            &signing_root.0.as_bytes(),
            &pubkeys,
        )
    }

    pub fn verify_bls_signature_aggregate_pk(&self, #[serializer(borsh)] input: LightClientStruct) -> u64 {
        let ethereum_network = Network::from_str("goerli").unwrap();
        let config = NetworkConfig::new(&ethereum_network);

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

        near_sdk::env::bls12_381_aggregate_verify(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_signature
                .0,
            &signing_root.0.as_bytes(),
            &input.pk_aggregate,
        )
    }

    pub fn verify_bls_with_pks_aggregation(&self, #[serializer(borsh)] input: LightClientStruct) -> u64 {
        let ethereum_network = Network::from_str("goerli").unwrap();
        let config = NetworkConfig::new(&ethereum_network);

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

        let sync_committee_bits = BitVec::<u8, Lsb0>::from_slice(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_bits
                .0,
        );

        let participant_pubkeys =
            get_participant_pubkeys(&input.sync_committee.pubkeys.0, &sync_committee_bits);

        let mut pubkeys: Vec<PublicKey> = vec![];
        for pubkey in participant_pubkeys{
            pubkeys.push(
                PublicKey::deserialize(pubkey.0.as_slice()).unwrap()
            );
        }

        let agg_pk = AggregatePublicKey::aggregate(&pubkeys).unwrap().to_public_key().serialize();

        near_sdk::env::bls12_381_aggregate_verify(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_signature
                .0,
            &signing_root.0.as_bytes(),
            &agg_pk,
        )
    }
}

#[cfg(test)]
mod tests {
    use bitvec::order::Lsb0;
    use bitvec::prelude::BitVec;
    use crate::LightClientStruct;
    use borsh::{BorshDeserialize, BorshSerialize};
    use eth2_utility::consensus::get_participant_pubkeys;
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

    async fn call_method_with_borsh_args(
        contract: &Contract,
        method_name: &str,
        args: LightClientStruct,
    ) {
        let res = contract.call(method_name)
            .args_borsh(args)
            .max_gas()
            .transact()
            .await.unwrap();

        println!("Gas burnt: {:?}", res.total_gas_burnt);
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
            pk_aggregate: vec![],
        };

        assert_eq!(
            view_method_with_borsh_args(
                &contract,
                "verify_bls_signature",
                input.try_to_vec().unwrap()
            )
            .await,
            1
        );

        call_method_with_borsh_args(&contract,
                                    "verify_bls_signature",
                                    input.clone()
        ).await;

        input = LightClientStruct {
            light_client_update: light_client_updates[0].clone(),
            sync_committee: next_sync_committee,
            pk_aggregate: vec![],
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
    }

    #[tokio::test]
    async fn test_verify_bls_signature_aggregate_pk() {
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
            pk_aggregate: vec![],
        };

        let sync_committee_bits = BitVec::<u8, Lsb0>::from_slice(
            &input
                .light_client_update
                .sync_aggregate
                .sync_committee_bits
                .0,
        );

        let sync_committee_bits_sum: u64 = sync_committee_bits.count_ones().try_into().unwrap();

        let participant_pubkeys =
            get_participant_pubkeys(&input.sync_committee.pubkeys.0, &sync_committee_bits);

        let mut pubkeys: Vec<blst::min_pk::PublicKey> = vec![];
        for pubkey in participant_pubkeys{
            pubkeys.push(
                blst::min_pk::PublicKey::key_validate(
                    &pubkey.0.as_slice(),
                ).unwrap(),
            );
        }

        let mut pubkeys_refs: Vec<&blst::min_pk::PublicKey> = vec![];
        for i in 0..pubkeys.len() {
            pubkeys_refs.push(&pubkeys[i]);
        }

        let agg_pk = match blst::min_pk::AggregatePublicKey::aggregate(&pubkeys_refs, false) {
            Ok(agg_sig) => agg_sig,
            Err(err) => panic!(),
        };
        let pk = agg_pk.to_public_key();
        input.pk_aggregate = pk.compress().to_vec();

        assert_eq!(
            view_method_with_borsh_args(
                &contract,
                "verify_bls_signature_aggregate_pk",
                input.try_to_vec().unwrap()
            ).await,
            1
        );

        call_method_with_borsh_args(&contract,
                                    "verify_bls_signature_aggregate_pk",
                                    input.clone()
        ).await;
    }


    #[tokio::test]
    async fn generate_data() {
        let n = 1;
        let msg: [u8; 10_000] = [0u8; 10_000];
        let ikm = [0u8; 32];

        let sks_i: Vec<_> = (0..n).map(|_| {
            blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap()
        }).collect();

        let pks_i =
            sks_i.iter().map(|sk| sk.sk_to_pk()).collect::<Vec<_>>();
        let pks_refs_i: Vec<&blst::min_pk::PublicKey> =
            pks_i.iter().map(|pk| pk).collect();

        let mut pks_raw: Vec<u8> = vec![];
        for pk in pks_i {
            pks_raw.append(&mut pk.compress().to_vec());
        }

        let sigs_i = sks_i
            .iter()
            .map(|sk| sk.sign(&msg, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]))
            .collect::<Vec<blst::min_pk::Signature>>();

        let sig_refs_i =
            sigs_i.iter().map(|s| s).collect::<Vec<&blst::min_pk::Signature>>();
        let agg_i = match blst::min_pk::AggregateSignature::aggregate(&sig_refs_i, false)
        {
            Ok(agg_i) => agg_i,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        let agg_sig_i = agg_i.to_signature();

        println!("agg_sig = {:?}", agg_sig_i.compress());
        println!("pks_raw = {:?}", pks_raw);
        println!("pks len= {:?}", pks_raw.len());
    }
}
