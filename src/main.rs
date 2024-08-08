mod enc;
mod sops;

use enc::age::SopsGcm;
use tracing::info;
use tracing_subscriber;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

fn main() {
    tracing_subscriber::fmt::init();
    let file = sops::SopsFile::load("test.yaml").unwrap();

    // let key = SopsGcm::generate_key(OsRng);

    // let cipher = SopsGcm::new(&key);
    // let nonce = SopsGcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // info!("Key: {:?} {}", key, key.len());
    // info!("Nonce: {:?} {}", nonce, nonce.len());

    // let ciphertext = cipher
    //     .encrypt(&nonce, b"plaintext message".as_ref())
    //     .unwrap();
    // let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    // assert_eq!(&plaintext, b"plaintext message");

    // info!("Asserted!");

    println!(
        "{:?}",
        file.get("restic_local", "/home/austin/.config/sops/age/keys.txt")
    );
}
