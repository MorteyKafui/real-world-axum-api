use bcrypt::{DEFAULT_COST, hash, verify};

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    // Cost factor 12 - good balance of security vs performance
    hash(password, DEFAULT_COST + 2)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}
