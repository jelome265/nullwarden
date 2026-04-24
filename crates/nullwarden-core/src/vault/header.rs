use crate::{crypto::NONCE_LEN, kdf::SALT_LEN};

pub const MIN_M_COST: u32 = 8 * 1024;
pub const MAX_M_COST: u32 = 1_048_576;
pub const MIN_T_COST: u32 = 1;
pub const MAX_T_COST: u32 = 10;
pub const MIN_P_COST: u32 = 1;
pub const MAX_P_COST: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub format_version: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHeaderDecodeError {
    InvalidFormat,
    UnsupportedFormatVersion(u8),
}

impl VaultHeader {
    pub const MAGIC: [u8; 4] = *b"NWAR";
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

    pub fn decode(input: &[u8]) -> Result<(Self, usize), VaultHeaderDecodeError> {
        let header_len = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
        if input.len() < header_len || input[..4] != Self::MAGIC {
            return Err(VaultHeaderDecodeError::InvalidFormat);
        }
        let format_version = input[4];
        if format_version != Self::FORMAT_VERSION {
            return Err(VaultHeaderDecodeError::UnsupportedFormatVersion(
                format_version,
            ));
        }
        let m_cost = u32::from_le_bytes(
            input[5..9]
                .try_into()
                .map_err(|_| VaultHeaderDecodeError::InvalidFormat)?,
        );
        let t_cost = u32::from_le_bytes(
            input[9..13]
                .try_into()
                .map_err(|_| VaultHeaderDecodeError::InvalidFormat)?,
        );
        let p_cost = u32::from_le_bytes(
            input[13..17]
                .try_into()
                .map_err(|_| VaultHeaderDecodeError::InvalidFormat)?,
        );
        if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost)
            || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
            || !(MIN_P_COST..=MAX_P_COST).contains(&p_cost)
        {
            return Err(VaultHeaderDecodeError::InvalidFormat);
        }
        let salt = input[17..17 + SALT_LEN]
            .try_into()
            .map_err(|_| VaultHeaderDecodeError::InvalidFormat)?;
        let nonce = input[17 + SALT_LEN..header_len]
            .try_into()
            .map_err(|_| VaultHeaderDecodeError::InvalidFormat)?;
        Ok((
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
