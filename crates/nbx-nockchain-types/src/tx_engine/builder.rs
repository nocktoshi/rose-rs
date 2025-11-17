use alloc::vec::Vec;
use nbx_crypto::PrivateKey;
use nbx_ztd::{Digest, Hashable as HashableTrait};

use super::note::Note;
use super::tx::{Seed, Seeds, Spend, SpendCondition, Spends, Witness};
use crate::{Nicks, RawTx};

pub struct TxBuilder {}

impl TxBuilder {
    pub fn new_with_fee(
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        fee: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
        signing_key: &PrivateKey,
    ) -> Result<RawTx, BuildError> {
        if gift == 0 {
            return Err(BuildError::ZeroGift);
        }

        let mut spends_vec = Vec::new();
        let mut remaining_gift = gift;
        let mut remaining_fee = fee;

        for (note, spend_condition) in notes {
            let gift_portion = remaining_gift.min(note.assets);
            let fee_portion = remaining_fee.min(note.assets.saturating_sub(gift_portion));
            let refund = note.assets.saturating_sub(gift_portion + fee_portion);

            if gift_portion == 0 && refund == 0 {
                continue;
            }

            remaining_gift -= gift_portion;
            remaining_fee -= fee_portion;

            let mut seeds_vec = Vec::new();
            if refund > 0 {
                seeds_vec.push(Seed::new_single_pkh(
                    refund_pkh,
                    refund,
                    note.hash(),
                    include_lock_data,
                ));
            }
            if gift_portion > 0 {
                seeds_vec.push(Seed::new_single_pkh(
                    recipient,
                    gift_portion,
                    note.hash(),
                    include_lock_data,
                ));
            }

            let spend = Spend::new(
                Witness::new(spend_condition.clone()),
                Seeds(seeds_vec),
                fee_portion,
            );
            spends_vec.push((note.name.clone(), spend));
        }
        if remaining_gift > 0 {
            return Err(BuildError::InsufficientFunds);
        }

        for (_, spend) in spends_vec.as_mut_slice() {
            spend.add_signature(
                signing_key.public_key(),
                signing_key.sign(&spend.sig_hash()),
            );
        }

        Ok(RawTx::new(Spends(spends_vec)))
    }

    pub fn new_simple(
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        fee_per_word: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
        signing_key: &PrivateKey,
    ) -> Result<RawTx, BuildError> {
        // Find fixpoint
        let build = |fee| {
            Self::new_with_fee(
                notes.clone(),
                recipient,
                gift,
                fee,
                refund_pkh,
                include_lock_data,
                signing_key,
            )
        };
        let mut fee: Nicks = 0;
        loop {
            let tx = build(fee)?;
            let new_fee = tx.spends.fee(fee_per_word);
            if new_fee == fee {
                break Ok(tx);
            }
            fee = new_fee
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    ZeroGift,
    InsufficientFunds,
    AccountingMismatch,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::ZeroGift => write!(f, "Cannot create a transaction with zero gift"),
            BuildError::InsufficientFunds => write!(f, "Insufficient funds to pay fee and gift"),
            BuildError::AccountingMismatch => {
                write!(f, "Assets in must equal gift + fee + refund")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LockPrimitive, LockTim, Name, NoteData, Pkh, Version};
    use alloc::{string::ToString, vec};
    use bip39::Mnemonic;
    use nbx_crypto::derive_master_key;

    #[test]
    fn test_vector() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();

        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".into(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".into(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };

        let recipient = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".into();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".into();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let tx = TxBuilder::new_with_fee(
            vec![(note, spend_condition)],
            recipient,
            gift,
            fee,
            refund_pkh,
            true,
            &private_key,
        )
        .unwrap();

        assert_eq!(
            tx.id.to_string(),
            "3j4vkn72mcpVtQrTgNnYyoF3rDuYax3aebT5axu3Qe16jm9x2wLtepW"
        );
    }

    #[test]
    fn test_first_name() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let public_key = derive_master_key(&mnemonic.to_seed("")).public_key;

        let sc = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(public_key.hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        assert_eq!(
            sc.first_name().to_string(),
            "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH",
        )
    }
}
