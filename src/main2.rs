mod enc;
mod sops;

use std::path::Path;

use age::{x25519::Identity, IdentityFileEntry};
use bech32::{Bech32, Bech32m, Hrp};
use ed25519_dalek::SecretKey;
use sops::load_sops_file;
use ssh_key::PrivateKey;
use tracing_subscriber;

use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let ssh_private_key = Path::new("/home/austin/.ssh/id_ed25519");
    let bytes = std::fs::read(ssh_private_key).unwrap();
    let ssh_key = PrivateKey::from_openssh(bytes)?;

    let identities =
        age::IdentityFile::from_file("/home/austin/.config/sops/age/keys.txt".to_string())?
            .into_identities();

    if let ssh_key::private::KeypairData::Ed25519(key) = ssh_key.key_data() {
        let ed25519_secret = key.public.as_ref().to_owned();

        // let public = key.public.as_ref();

        let x25519_secret = StaticSecret::from(ed25519_secret);

        let public = PublicKey::from(&x25519_secret);

        println!("x25519 Secret key: {:?}", x25519_secret.to_bytes());
        println!("x25519 Public key: {:?}", public.to_bytes());

        let hrp = Hrp::parse("AGE-SECRET-KEY-")?;
        let hrp_public = Hrp::parse("age")?;
        let encoded = bech32::encode_upper::<Bech32m>(hrp, &x25519_secret.to_bytes())?;
        let public = bech32::encode::<Bech32m>(hrp_public, &public.to_bytes())?;
        println!("Bech32 encoded secret key: {}", encoded);
        println!("Bech32 encoded public key: {}", public);
    } else {
        panic!("Invalid key type");
    }

    Ok(())
}
