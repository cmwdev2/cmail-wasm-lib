//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use subnet_wasm::x25519::{X25519_STATIC_SECRET_LEN, x22519_static_secret_from_bytes, x25519_create_public_key, x25519_diffie_hellman, X25519_PUB_KEY_LEN};
use hex_literal::hex;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn execute_diffie_hellman() {
    fn generate_random_seed() -> Vec<u8> {
        (0..X25519_STATIC_SECRET_LEN).map(|_| rand::random::<u8>()).collect()
    }
    let alice_seed = generate_random_seed();
    let alice_static_secret = x22519_static_secret_from_bytes(alice_seed.as_ref());
    let alice_public_key = x25519_create_public_key(alice_static_secret.as_ref());

    let bob_seed = generate_random_seed();
    let bob_static_secret = x22519_static_secret_from_bytes(bob_seed.as_ref());
    let bob_public_key = x25519_create_public_key(bob_static_secret.as_ref());

    assert_eq!(x25519_diffie_hellman(alice_static_secret.as_ref(), bob_public_key.as_ref()),x25519_diffie_hellman(bob_static_secret.as_ref(), alice_public_key.as_ref()));
}

#[wasm_bindgen_test]
fn create_static_secret() {
    let seed = hex!("744821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
    let expected_static_secret = hex!("704821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
    let static_secret = x22519_static_secret_from_bytes(seed.as_ref());
    assert_eq!(static_secret.len(), X25519_STATIC_SECRET_LEN);
    assert_eq!(static_secret, expected_static_secret);
}

#[wasm_bindgen_test]
fn creates_public_key_from_static_secret() {
    let secret = hex!("704821c3637fca200f28bc9653acca5c83fb0d3ba6249e342fe1beead5510b42");
    let expected_pub_key = hex!("6c29b37f38c9e0332c6447734cfbe36839e11fbb134c9052624f354007cf8212");
    let public_key = x25519_create_public_key(secret.as_ref());
    assert_eq!(public_key.len(), X25519_PUB_KEY_LEN);
    assert_eq!(public_key, expected_pub_key);
}
