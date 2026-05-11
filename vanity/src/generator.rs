use secp256k1::{Secp256k1, SecretKey, PublicKey, All};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct KeyMaterial {
    pub scan_priv:  [u8; 32],
    pub spend_priv: [u8; 32],
    pub scan_pub:   PublicKey,
    pub spend_pub:  PublicKey,
}

/// Generate a completely fresh keypair (scan + spend).
pub fn generate_keypair(secp: &Secp256k1<All>) -> KeyMaterial {
    let scan_priv  = random_secret_key(&mut rand::thread_rng());
    let spend_priv = random_secret_key(&mut rand::thread_rng());
    let scan_pub   = PublicKey::from_secret_key(secp, &scan_priv);
    let spend_pub  = PublicKey::from_secret_key(secp, &spend_priv);
    KeyMaterial {
        scan_priv:  scan_priv.secret_bytes(),
        spend_priv: spend_priv.secret_bytes(),
        scan_pub,
        spend_pub,
    }
}

pub fn generate_spend_only(
    secp:      &Secp256k1<All>,
    scan_priv: &SecretKey,
    scan_pub:  &PublicKey,
) -> KeyMaterial {
    let spend_priv = random_secret_key(&mut rand::thread_rng());
    let spend_pub  = PublicKey::from_secret_key(secp, &spend_priv);
    KeyMaterial {
        scan_priv:  scan_priv.secret_bytes(),
        spend_priv: spend_priv.secret_bytes(),
        scan_pub:   *scan_pub,
        spend_pub,
    }
}

#[inline]
fn random_secret_key(rng: &mut impl RngCore) -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}