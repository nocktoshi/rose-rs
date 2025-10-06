mod cheetah;
mod slip10;

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
pub use cheetah::{PrivateKey, PublicKey, Signature};
pub use slip10::{derive_master_key, ExtendedKey};
use std::collections::BTreeMap;

struct MasterKey {
    priv_key: PrivateKey,
    // Make sure we only serialize the key ID's, but not the keys themselves
    loaded_children: BTreeMap<u32, (PublicKey, PrivateKey)>,
}

pub struct Keystore {
    keys: BTreeMap<PublicKey, MasterKey>,
}

impl Keystore {
    // TODO:
    // load(json)
    // store() -> json
    // list_master_pubkeys() -> Vec<Pubkey>
    // list_child_pubkeys(master_pubkey) -> Vec<Pubkey>
    // delete_master_key(master_pubkey)
    // derive_master_key_from_seedphrase(seedphrase) -> derive_master_key(derive_seed(seedphrase))
    // sign(chal, key_handle) -> sig
}

/// Derive seed from password and salt using Argon2
pub fn derive_seed_phrase(password: &[u8], salt: &[u8]) -> (String, [u8; 64]) {
    let mut argon_output = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2d,
        Version::V0x13,
        Params::new(6 << 17, 6, 4, None).unwrap(),
    )
    .hash_password_into(password, salt, &mut argon_output)
    .expect("Invalid entropy and/or salt");

    let mnemonic = Mnemonic::from_entropy(&argon_output).unwrap();
    (mnemonic.to_string(), mnemonic.to_seed(""))
}
