pub use iris_crypto::{PrivateKey, PublicKey};
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

pub struct KeyHandle {
    master_pubkey: PublicKey,
    child_id: u32,
}
