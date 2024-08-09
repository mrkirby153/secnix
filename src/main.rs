mod enc;
mod sops;

use sops::load_sops_file;
use tracing_subscriber;

fn main() {
    tracing_subscriber::fmt::init();
    let file = load_sops_file("data/test.yaml").unwrap();

    let foo = "restic_remote_password";
    let key = foo.split('.').collect::<Vec<&str>>();

    let result = file.decrypt(&key[..], "/home/austin/.config/sops/age/keys.txt");

    println!("{:?}", result);
}
