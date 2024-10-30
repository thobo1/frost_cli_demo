#[derive(Debug)]
pub enum KeyGenError {
    ProofError,
    PublicKeyDerivationFailed,
    VerificationFailed,
    GroupPublicKeyMismatch,
}

impl std::fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyGenError::ProofError => write!(f, "Proof verification failed."),
            KeyGenError::PublicKeyDerivationFailed => write!(f, "Public key derivation failed."),
            KeyGenError::VerificationFailed => write!(f, "Key verification failed."),
            KeyGenError::GroupPublicKeyMismatch => write!(f, "Group public key mismatch."),
        }
    }
}

impl std::error::Error for KeyGenError {}
