use blake2::{Blake2b, Digest};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use std::error::Error;
use std::io::{Read, Write};
use std::iter::Iterator;

use std::net::TcpStream;

const HELLO_BOB: &str = "Hello Bob!\n";

fn main() -> Result<(), Box<dyn Error>> {
    // First, connect to the server
    println!("Trying to connect to the server");
    let mut stream = TcpStream::connect("mascarade.chall.malicecyber.com:4999")
        .expect("Failed to connect to the server");

    // Buffer holding non used data
    let mut buff = [0; 128];
    // Buffer holding Bob's public key, with exact size
    let mut ephemeral_pubkey_bytes = [0; 32];

    // Read "Hello Alice!\n" from server
    let _ = stream.read(&mut buff).expect("Failed to read Hello Alice");

    // Send "Hello Bob!\n" to server
    stream
        .write_all(HELLO_BOB.as_bytes())
        .expect("Failed to send HELLO_BOB");

    let _ = stream
        .read_exact(&mut ephemeral_pubkey_bytes)
        .expect("Failed to read Bob's ephemeral secret key");

    let bob_public: PublicKey = PublicKey::from(ephemeral_pubkey_bytes);
    println!("bob_public = {:?}", bob_public.as_bytes());

    // Generate our key pair
    let our_secret = EphemeralSecret::new(OsRng);
    let our_public = PublicKey::from(&our_secret);

    println!("our_public = {:?}", our_public.to_bytes());

    // Send our public key
    stream
        .write_all(our_public.as_bytes())
        .expect("Failed to send our public key");

    // Setup shared secrets
    let bob_static_secret: StaticSecret = StaticSecret::from([
        128, 0, 20, 121, 100, 3, 92, 119, 70, 203, 20, 8, 122, 109, 231, 12, 103, 203, 231, 222,
        127, 221, 171, 139, 176, 8, 114, 52, 61, 98, 3, 64,
    ]);
    let alice_static_public: PublicKey = PublicKey::from([
        20, 2, 29, 90, 241, 67, 52, 1, 217, 46, 238, 54, 248, 8, 227, 39, 81, 48, 215, 36, 220,
        241, 207, 33, 186, 112, 32, 254, 188, 140, 12, 10,
    ]);

    // compute the shared secrets (from server code)
    let shared_ephemeral_secret = our_secret.diffie_hellman(&bob_public);
    println!(
        "shared_ephemeral_secret = {:?}",
        shared_ephemeral_secret.as_bytes()
    );
    let shared_static_secret = bob_static_secret.diffie_hellman(&alice_static_public);
    println!(
        "shared_static_secret = {:?}",
        shared_static_secret.as_bytes()
    );
    let shared_static_ephemeral_secret = bob_static_secret.diffie_hellman(&our_public);
    println!(
        "shared_static_ephemeral_secret = {:?}",
        shared_static_ephemeral_secret.as_bytes()
    );

    // derive the key (from server code)
    let shared_secret = Blake2b::new()
        .chain(shared_ephemeral_secret.as_bytes())
        .chain(shared_static_secret.as_bytes())
        .chain(shared_static_ephemeral_secret.as_bytes())
        .finalize();
    println!("shared secret = {:?}", shared_secret);

    // construct the cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_secret[..32]));
    let nonce = Nonce::from_slice(&[0u8; 12]); // we only use one nonce, so pick something simple

    let mut flag = [0; 128];
    stream
        .read(&mut flag)
        .expect("Failed to read encrypted content from server");

    println!("Encrypted content: {:?}", flag);

    let result: Vec<u8> = flag.iter().take_while(|n| **n != 0x00).cloned().collect();

    let plaintext = cipher
        .decrypt(nonce, &result[..])
        .expect("Failed to decrypt flag");

    println!("Flag = {}", String::from_utf8(plaintext).unwrap());

    Ok(())
}
