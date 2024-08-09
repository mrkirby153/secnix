mod enc;
mod sops;

use sops::load_sops_file;
use tracing_subscriber;

fn main() {
    tracing_subscriber::fmt::init();
    let file = load_sops_file("data/foo.json").unwrap();

    let foo = "nested.object";
    let key = foo.split('.').collect::<Vec<&str>>();

    let key = file.get_key(&key[..]);

    // file.get_decrypted(&key);

    println!("{:?}", key);

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

    // println!(
    //     "{:?}",
    //     file.get("restic_local", "/home/austin/.config/sops/age/keys.txt")
    // );
}
