#![no_main]
use libfuzzer_sys::fuzz_target;
use nullwarden_core::vault::data::VaultData;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize MessagePack data into VaultData
    // Must never panic
    let _ = rmp_serde::from_slice::<VaultData>(data);
});
