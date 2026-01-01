fn main() {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(8, 1, 1, Some(16)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_bytes = b"deterministic_sa";
    let salt = SaltString::encode_b64(salt_bytes).unwrap();
    let phc = argon.hash_password(b"correct horse battery staple", &salt).unwrap().to_string();
    println!("{phc}");
}
