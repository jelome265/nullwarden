use crate::{crypto::NONCE_LEN, kdf::SALT_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub format_version: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl VaultHeader {
    pub const MAGIC: [u8; 4] = *b"NWDN";
    pub const FORMAT_VERSION: u8 = 1;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN);
        out.extend_from_slice(&Self::MAGIC);
        out.push(self.format_version);
        out.extend_from_slice(&self.m_cost.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn decode(input: &[u8]) -> Option<(Self, usize)> {
        let header_len = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
        if input.len() < header_len || input[..4] != Self::MAGIC {
            return None;
        }
        let format_version = input[4];
        let m_cost = u32::from_le_bytes(input[5..9].try_into().ok()?);
        let t_cost = u32::from_le_bytes(input[9..13].try_into().ok()?);
        let p_cost = u32::from_le_bytes(input[13..17].try_into().ok()?);
        let salt = input[17..17 + SALT_LEN].try_into().ok()?;
        let nonce = input[17 + SALT_LEN..header_len].try_into().ok()?;
        Some((
            Self {
                format_version,
                m_cost,
                t_cost,
                p_cost,
                salt,
                nonce,
            },
            header_len,
        ))
    }
}
