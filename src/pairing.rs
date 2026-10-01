use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const PAIRING_PORT: u16 = 9002;

pub fn generate_pairing_code() -> String {
    let mut rng = rand::rng();

    let code: u32 = rng.random_range(100000..1000000);

    format!("{:06}", code)
}

pub fn run_server(pairing_code: String) {
    let listener =
        TcpListener::bind(("0.0.0.0", PAIRING_PORT)).unwrap();

    println!(
        "Pairing server listening on TCP port {}",
        PAIRING_PORT
    );

    println!("Pairing code: {}", pairing_code);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,

            Err(error) => {
                println!("Pairing connection failed: {}", error);
                continue;
            }
        };

        let expected_code = pairing_code.clone();

        thread::spawn(move || {
            handle_pairing(stream, expected_code);
        });
    }
}

fn handle_pairing(
    mut stream: std::net::TcpStream,
    expected_code: String,
) {
    let mut buffer = [0u8; 1024];

    let bytes_read = match stream.read(&mut buffer) {
        Ok(bytes) => bytes,

        Err(error) => {
            println!("Failed to read pairing request: {}", error);
            return;
        }
    };

    let received_code =
        String::from_utf8_lossy(&buffer[..bytes_read])
            .trim()
            .to_string();

    println!("Received pairing code: {}", received_code);

    if received_code == expected_code {
        println!("Pairing accepted.");

        stream
            .write_all(b"PAIR_OK")
            .unwrap();
    } else {
        println!("Pairing rejected.");

        stream
            .write_all(b"PAIR_REJECTED")
            .unwrap();
    }
}