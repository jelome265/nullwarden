//! Fuzzing utilities for NullWarden
//!
//! This module provides shared helper functions for fuzz targets
//! to ensure consistency across different security tests.

use nullwarden_core::vault::data::VaultData;

pub fn is_valid_vault_structure(vault: &VaultData) -> bool {
    // Basic structural validation that fuzzer can use as a post-condition
    !vault.entries.is_empty() || vault.version >= 1
}
