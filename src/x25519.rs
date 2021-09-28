use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use wasm_bindgen::prelude::*;

pub const X25519_STATIC_SECRET_LEN : usize = 32;
pub const X25519_PUB_KEY_LEN : usize = 32;

/// create a static secret from 32 bytes  seed
fn static_secret_from_bytes(data: &[u8]) -> StaticSecret {
	let mut bytes = [0u8; X25519_STATIC_SECRET_LEN];
	bytes.copy_from_slice(data);
	StaticSecret::from(bytes)
}

#[wasm_bindgen]
pub fn x22519_static_secret_from_bytes(data: &[u8]) -> Vec<u8> {

	if static_secret.len() != X25519_STATIC_SECRET_LEN {
		panic!("input must be 32 bytes")
	}

	static_secret_from_bytes(data).to_bytes().to_vec()
}

/// Create a 32 bytes public key from m a static secret
fn create_public_key(static_secret: &[u8]) -> PublicKey {

	if static_secret.len() != X25519_STATIC_SECRET_LEN {
		panic!("static secret input must be 32 bytes")
	}

	let mut bytes = [0u8; X25519_STATIC_SECRET_LEN];
	bytes.copy_from_slice(static_secret);
	let secret = StaticSecret::from(bytes);
	PublicKey::from(&secret)
}

#[wasm_bindgen]
pub fn x25519_create_public_key(static_secret: &[u8]) -> Vec<u8> {
	create_public_key(static_secret).to_bytes().to_vec()
}


// Create a shared secret using a private ephemeral or static secret and a public key
fn diffie_hellman(private_key: &[u8], public_key:&[u8]) -> SharedSecret {

	if private_key.len() != X25519_STATIC_SECRET_LEN {
		panic!("private key must be 32 bytes")
	}

	if public_key.len() != X25519_PUB_KEY_LEN {
		panic!("public key must be 32 bytes")
	}

	let mut bytes = [0u8; X25519_STATIC_SECRET_LEN];
	bytes.copy_from_slice(private_key);
	let secret = StaticSecret::from(bytes);
	let mut bytes1 = [0u8; X25519_PUB_KEY_LEN];
	bytes1.copy_from_slice(public_key);
	let public = PublicKey::from(bytes1);
	secret.diffie_hellman(&public)
}

#[wasm_bindgen]
pub fn x25519_diffie_hellman(private_key: &[u8], public_key:&[u8]) -> Vec<u8> {
	diffie_hellman(private_key, public_key).to_bytes().to_vec()
}

#[cfg(test)]
pub mod tests {
	extern crate rand;
	use hex_literal::hex;
	use super::*;

	fn generate_random_seed() -> Vec<u8> {
		(0..X25519_STATIC_SECRET_LEN).map(|_| rand::random::<u8>()).collect()
	}

	#[test]
	fn can_create_static_secret() {
		let seed = hex!("744821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
		let expected_static_secret = hex!("704821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
		let static_secret = x22519_static_secret_from_bytes(seed.as_ref());
		assert_eq!(static_secret.len(), X25519_STATIC_SECRET_LEN);
		assert_eq!(static_secret, expected_static_secret);
	}

	#[test]
	fn creates_public_key_from_static_secret() {
		let secret = hex!("704821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
		let expected_pub_key = hex!("6c29b37f38c9e0332c6447734cfbe36839e11fbb134c9052624f354007cf8212");
		let public_key = x25519_create_public_key(secret.as_ref());
		assert_eq!(public_key.len(), X25519_PUB_KEY_LEN);
		assert_eq!(public_key, expected_pub_key);
	}

	#[test]
	fn execute_diffie_hellman() {
		let alice_seed = generate_random_seed();
		let alice_static_secret = x22519_static_secret_from_bytes(alice_seed.as_ref());
		let alice_public_key = x25519_create_public_key(alice_static_secret.as_ref());

		let bob_seed = generate_random_seed();
		let bob_static_secret = x22519_static_secret_from_bytes(bob_seed.as_ref());
		let bob_public_key = x25519_create_public_key(bob_static_secret.as_ref());

		assert_eq!(x25519_diffie_hellman(alice_static_secret.as_ref(), bob_public_key.as_ref()),x25519_diffie_hellman(bob_static_secret.as_ref(), alice_public_key.as_ref()));
	}
}
