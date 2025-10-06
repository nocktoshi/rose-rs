use ibig::UBig;
use nockchain_math::belt::Belt;
use nockchain_math::crypto::cheetah::{
    ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahPoint, A_GEN, G_ORDER,
};
use nockchain_math::tip5::hash::hash_varlen;

#[derive(Debug, Clone)]
pub struct PublicKey(pub CheetahPoint);

impl PublicKey {
    pub fn verify(&self, m: &[u64; 5], sig: &Signature) -> bool {
        let m_list: Vec<Belt> = m.iter().map(|&x| Belt(x)).collect();

        if sig.c == UBig::from(0u64)
            || sig.c >= *G_ORDER
            || sig.s == UBig::from(0u64)
            || sig.s >= *G_ORDER
        {
            return false;
        }

        // Compute scalar = s*G - c*pubkey
        // This is equivalent to: scalar = s*G + (-c)*pubkey
        let sg = match ch_scal_big(&sig.s, &A_GEN) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let c_pk = match ch_scal_big(&sig.c, &self.0) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let scalar = match ch_add(&sg, &ch_neg(&c_pk)) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let chal = {
            let mut transcript: Vec<Belt> = Vec::new();
            transcript.extend_from_slice(&scalar.x.0);
            transcript.extend_from_slice(&scalar.y.0);
            transcript.extend_from_slice(&self.0.x.0);
            transcript.extend_from_slice(&self.0.y.0);
            transcript.extend_from_slice(&m_list);
            trunc_g_order(&hash_varlen(&mut transcript))
        };

        chal == sig.c
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for belt in self.0.y.0.iter().rev().chain(self.0.x.0.iter().rev()) {
            data.extend_from_slice(&belt.0.to_be_bytes());
        }
        data
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub c: UBig, // challenge
    pub s: UBig, // signature scalar
}

#[derive(Debug, Clone)]
pub struct PrivateKey(pub UBig);

impl PrivateKey {
    pub fn derive_public_key(&self) -> PublicKey {
        PublicKey(ch_scal_big(&self.0, &A_GEN).unwrap())
    }

    // sign 5 belts (message digest)
    pub fn sign(&self, m: &[u64; 5]) -> Signature {
        let m_list: Vec<Belt> = m.iter().map(|&x| Belt(x)).collect();
        let pubkey = self.derive_public_key().0;
        let nonce = {
            let mut transcript = Vec::new();
            transcript.extend_from_slice(&pubkey.x.0);
            transcript.extend_from_slice(&pubkey.y.0);
            transcript.extend_from_slice(&m_list);
            trunc_g_order(&hash_varlen(&mut transcript))
        };
        let chal = {
            // scalar = nonce * G
            let scalar = ch_scal_big(&nonce, &A_GEN).unwrap();
            let mut transcript = Vec::new();
            transcript.extend_from_slice(&scalar.x.0);
            transcript.extend_from_slice(&scalar.y.0);
            transcript.extend_from_slice(&pubkey.x.0);
            transcript.extend_from_slice(&pubkey.y.0);
            transcript.extend_from_slice(&m_list);
            trunc_g_order(&hash_varlen(&mut transcript))
        };
        let sig = (&nonce + &chal * &self.0) % &*G_ORDER;
        Signature { c: chal, s: sig }
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_be_bytes();
        let mut arr = [0u8; 32];
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        arr.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let priv_key = PrivateKey(UBig::from(123u64));
        let message = [1, 2, 3, 4, 5];
        let signature = priv_key.sign(&message);
        let pubkey = priv_key.derive_public_key();
        assert!(
            pubkey.verify(&message, &signature),
            "Signature verification failed!"
        );

        // Corrupting message, signature, or pubkey should all cause failure
        let mut wrong_message = message.clone();
        wrong_message[0] = 0;
        assert!(
            !pubkey.verify(&wrong_message, &signature),
            "Should reject wrong message"
        );
        let mut wrong_sig = signature.clone();
        wrong_sig.s += UBig::from(1u64);
        assert!(
            !pubkey.verify(&message, &wrong_sig),
            "Should reject wrong signature"
        );
        let mut wrong_pubkey = pubkey.clone();
        wrong_pubkey.0.x.0[0].0 += 1;
        assert!(
            !wrong_pubkey.verify(&message, &signature),
            "Should reject wrong public key"
        );
    }

    #[test]
    fn test_vector() {
        // from nockchain zkvm-jetpack cheetah_jets.rs test_batch_verify_affine
        use nockchain_math::crypto::cheetah::F6lt;
        let message = [8, 9, 10, 11, 12];
        let pubkey = PublicKey(CheetahPoint {
            x: F6lt([
                Belt(2754611494552410273),
                Belt(8599518745794843693),
                Belt(10526511002404673680),
                Belt(4830863958577994148),
                Belt(375185138577093320),
                Belt(12938930721685970739),
            ]),
            y: F6lt([
                Belt(3062714866612034253),
                Belt(15671931273416742386),
                Belt(4071440668668521568),
                Belt(7738250649524482367),
                Belt(5259065445844042557),
                Belt(8456011930642078370),
            ]),
            inf: false,
        });
        let c_hex = "6f3cd43cd8709f4368aed04cd84292ab1c380cb645aaa7d010669d70375cbe88";
        let s_hex = "5197ab182e307a350b5cf3606d6e99a6f35b0d382c8330dde6e51fb6ef8ebb8c";
        let signature = Signature {
            c: UBig::from_str_radix(c_hex, 16).unwrap(),
            s: UBig::from_str_radix(s_hex, 16).unwrap(),
        };
        assert!(pubkey.verify(&message, &signature));
    }
}
