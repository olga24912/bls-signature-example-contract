# Example contract for bls signature verification
In contract function `verify_bls_signature` takes `LightClientUpdate` and `SyncCommittee` and verify sync committee signature of attested block.

## Dependencies
* https://github.com/olga24912/nearcore/tree/bls-sig
* https://github.com/olga24912/near-sdk-rs/tree/bls-sig-4.0.0

## Test running
1. Clone `nearcore` repository
```bush
$ git clone https://github.com/olga24912/nearcore.git
$ cd nearcore
$ git checkout bls-sig
```

2. Run `make sandbox`
```bush
$ make sandbox
```

3. Save path to sandbox to env var
```bush
$ export NEAR_SANDBOX_BIN_PATH=<PATH_TO_NEARCORE>/target/debug/near-sandbox
```

4. Run tests
```bush
$ cd <PATH_TO_EXAMPLE_CONTRACT>
$ ./build.sh
$ cargo test -- --show-output
```