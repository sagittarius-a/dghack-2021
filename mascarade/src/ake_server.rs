use blake2::{Blake2b, Digest};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use std::{fs, sync::Arc};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task,
};

use std::{
    error::Error,
    sync::atomic::{AtomicUsize, Ordering},
};

const FLAG_PATH: &str = "flag.txt";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:7878";
    server_loop(addr, FLAG_PATH).await
}

async fn server_loop(addr: &str, flag_loc: &str) -> Result<(), Box<dyn Error>> {
    let flag =
        Arc::new(fs::read_to_string(flag_loc).expect("Something went wrong reading the file"));

    println!("Flag {}", flag);
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on: {}", addr);

    let counter = AtomicUsize::new(0);
    loop {
        // Asynchronously wait for an inbound socket.
        let (stream, _) = listener.accept().await?;
        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        if c % 1000 == 0 {
            println!("{} connections", c);
        }
        let flag = flag.clone();
        tokio::spawn(async move {
            handle_connection_initiator(stream, flag).await.ok();
        });
    }
}

const HELLO_ALICE: &str = "Hello Alice!\n";
const HELLO_BOB: &str = "Hello Bob!\n";

async fn handle_connection_initiator(
    mut stream: TcpStream,
    flag: Arc<String>,
) -> Result<(), Box<dyn Error>> {
    let bob_static_secret: StaticSecret = StaticSecret::from([
        128, 0, 20, 121, 100, 3, 92, 119, 70, 203, 20, 8, 122, 109, 231, 12, 103, 203, 231, 222,
        127, 221, 171, 139, 176, 8, 114, 52, 61, 98, 3, 64,
    ]);
    let alice_static_public: PublicKey = PublicKey::from([
        20, 2, 29, 90, 241, 67, 52, 1, 217, 46, 238, 54, 248, 8, 227, 39, 81, 48, 215, 36, 220,
        241, 207, 33, 186, 112, 32, 254, 188, 140, 12, 10,
    ]);

    // Say Hello!
    stream.write_all(&HELLO_ALICE.as_bytes()).await?;

    let buffer_size = 1024;
    let mut buffer = vec![0; buffer_size];
    let size_read = stream.read(&mut buffer).await?;

    let s = std::str::from_utf8(&buffer[..size_read])?;
    if s != HELLO_BOB {
        return Ok(()); // I don't want to implement annoying error management here. So we just stop
    }

    assert_eq!(
        std::str::from_utf8(&buffer[..size_read]).unwrap(),
        HELLO_BOB
    );

    println!("Running the handshake");

    // run the handshake.
    // generate ephemerals
    // spawn a blocking task for that (it is CPU-intensive)
    let (bob_secret, bob_public) = task::spawn_blocking(move || {
        let bob_secret = EphemeralSecret::new(OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        (bob_secret, bob_public)
    })
    .await?;

    // send the initiator message with our ephemeral public key
    println!("Send the initiator message with our ephemeral key");
    println!("Sending : {:?}", bob_public);

    stream.write_all(bob_public.as_bytes()).await?;

    let mut buffer = [0; 32]; // size of a public key

    // get the responder message
    let _ = stream.read_exact(&mut buffer).await?;

    let alice_public = PublicKey::from(buffer);

    println!("Alice public key: {:?}", alice_public);

    // the next steps are CPU-intensive

    let ct = task::spawn_blocking(move || {
        println!("Computing shared secrets");
        // compute the shared secrets
        let shared_ephemeral_secret = bob_secret.diffie_hellman(&alice_public);
        println!(
            "shared_ephemeral_secret = {:?}",
            shared_ephemeral_secret.as_bytes()
        );
        let shared_static_secret = bob_static_secret.diffie_hellman(&alice_static_public);
        println!(
            "shared_static_secret = {:?}",
            shared_static_secret.as_bytes()
        );
        let shared_static_ephemeral_secret = bob_static_secret.diffie_hellman(&alice_public);
        println!(
            "shared_static_ephemeral_secret = {:?}",
            shared_static_ephemeral_secret.as_bytes()
        );

        // derive the key
        let shared_secret = Blake2b::new()
            .chain(shared_ephemeral_secret.as_bytes())
            .chain(shared_static_secret.as_bytes())
            .chain(shared_static_ephemeral_secret.as_bytes())
            .finalize();

        println!("shared secret = {:?}", shared_secret);

        // construct the cipher and encrypt
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_secret[..32]));
        let nonce = Nonce::from_slice(&[0u8; 12]); // we only use one nonce, so pick something simple

        cipher
            .encrypt(nonce, flag.as_bytes())
            .expect("encryption failure!") // NOTE: handle this error to avoid panics!
    })
    .await?;

    println!(
        "Sending encrypted content({} bytes long): {:?}",
        ct.len(),
        ct
    );
    stream.write_all(&ct).await?;

    Ok(())
}
