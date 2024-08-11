mod enc;
mod sops;
mod ssh;

use std::path::Path;

use ssh::AgeKey;
use ssh_key::PrivateKey;
use tracing_subscriber;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let ssh_private_key = Path::new("/home/austin/.ssh/id_ed25519");
    let bytes = std::fs::read(ssh_private_key).unwrap();
    let ssh_key = PrivateKey::from_openssh(bytes)?;

    let key = AgeKey::try_from(ssh_key)?;
    println!("{:?}", key);
    Ok(())
}
