use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{Read, Seek};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use drop::protocol::{TransferHeader, send_header};
use drop::secure_channel;

const DISCOVERY_PORT: u16 = 9001;
const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";
const CHUNK_SIZE: usize = 32 * 1024;

fn main() {
    let file_path = match get_file_path() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(r#"Usage: cargo run --bin send -- "C:/path/to/file.pdf""#);
            std::process::exit(1);
        }
    };

    let filename = match file_path.file_name().and_then(|name| name.to_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            eprintln!("Invalid filename.");
            std::process::exit(1);
        }
    };

    let mut file = match File::open(&file_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Could not open '{}': {error}", file_path.display());
            std::process::exit(1);
        }
    };

    let metadata_before = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            eprintln!("The selected path is not a regular file.");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("Could not read file metadata: {error}");
            std::process::exit(1);
        }
    };

    let file_size = metadata_before.len();

    println!("Selected file: {}", file_path.display());
    println!("Filename: {filename}");
    println!("File size: {file_size} bytes");

    // First pass: calculate the expected checksum.
    let mut expected_hasher = Sha256::new();
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("Failed to calculate checksum: {error}");
                std::process::exit(1);
            }
        };

        expected_hasher.update(&buffer[..bytes_read]);
    }

    let expected_checksum = expected_hasher.finalize();

    if let Err(error) = file.rewind() {
        eprintln!("Failed to rewind file: {error}");
        std::process::exit(1);
    }

    // Discover a Drop device.
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create discovery socket");

    socket
        .set_broadcast(true)
        .expect("Failed to enable broadcast");

    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("Failed to set discovery timeout");

    socket
        .send_to(
            DISCOVERY_MESSAGE,
            format!("255.255.255.255:{DISCOVERY_PORT}"),
        )
        .expect("Failed to send discovery request");

    println!("Searching for Drop devices...");

    let mut discovery_buffer = [0u8; 1024];

    let (device_ip, device_port, device_id, device_name) = loop {
        match socket.recv_from(&mut discovery_buffer) {
            Ok((length, sender_address)) => {
                let message = String::from_utf8_lossy(&discovery_buffer[..length]);
                let parts: Vec<&str> = message.split('|').collect();

                if parts.len() == 4 && parts[0] == "DROP_HERE" {
                    let port = match parts[3].parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => continue,
                    };

                    break (
                        sender_address.ip(),
                        port,
                        parts[1].to_string(),
                        parts[2].to_string(),
                    );
                }
            }
            Err(error) => {
                eprintln!("Discovery failed or timed out: {error}");
                std::process::exit(1);
            }
        }
    };

    println!("Found device: {device_name}");
    println!("Device ID: {device_id}");
    println!("Connecting to {device_ip}:{device_port}...");

    let stream = match std::net::TcpStream::connect((device_ip, device_port)) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("Connection failed: {error}");
            std::process::exit(1);
        }
    };

    let signing_key = load_phone_signing_key();

    let mut channel = match secure_channel::connect_client(stream, &signing_key, &device_id) {
        Ok(channel) => channel,
        Err(error) => {
            eprintln!("Secure connection failed: {error}");
            std::process::exit(1);
        }
    };

    println!("Secure connection established; both device identities verified.");

    let transfer_id = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(error) => {
            eprintln!("System clock error: {error}");
            std::process::exit(1);
        }
    };

    let header = TransferHeader {
        transfer_id,
        filename,
        file_size,
        checksum: expected_checksum.into(),
    };

    let mut header_bytes = Vec::new();

    if let Err(error) = send_header(&mut header_bytes, &header) {
        eprintln!("Failed to prepare file header: {error}");
        std::process::exit(1);
    }

    if let Err(error) = channel.send(&header_bytes) {
        eprintln!("Failed to send encrypted header: {error}");
        std::process::exit(1);
    }

    // Second pass: hash exactly the bytes being sent.
    let mut sent_hasher = Sha256::new();
    let mut sent = 0u64;

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("Failed to read file while sending: {error}");
                eprintln!("Stopping because the transfer may be incomplete.");
                std::process::exit(1);
            }
        };

        sent_hasher.update(&buffer[..bytes_read]);

        if let Err(error) = channel.send(&buffer[..bytes_read]) {
            eprintln!("Failed to send encrypted file data: {error}");
            std::process::exit(1);
        }

        sent += bytes_read as u64;
        println!("Sent {sent} / {file_size} bytes");
    }

    let sent_checksum = sent_hasher.finalize();

    let metadata_after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("Could not recheck file metadata: {error}");
            std::process::exit(1);
        }
    };

    if sent != file_size
        || sent_checksum.as_slice() != expected_checksum.as_slice()
        || metadata_after.len() != metadata_before.len()
        || metadata_after.modified().ok() != metadata_before.modified().ok()
    {
        eprintln!("WARNING: The source file may have changed during transfer.");
        eprintln!("The receiver will reject the file if its checksum does not match.");
    }

    println!("All file data sent. Waiting for receiver verification...");

    match channel.receive() {
        Ok(response) if response == b"OK" => {
            if sent_checksum.as_slice() == expected_checksum.as_slice() && sent == file_size {
                println!("SUCCESS: Receiver verified the checksum and saved the file.");
            } else {
                eprintln!(
                    "WARNING: Receiver accepted the transmitted bytes, but the source changed during sending."
                );
                eprintln!(
                    "The saved file matches the original transfer header, not necessarily the current source file."
                );
                std::process::exit(1);
            }
        }
        Ok(response) => {
            let message = String::from_utf8_lossy(&response);

            if let Some(reason) = message.strip_prefix("ERR:") {
                eprintln!("TRANSFER REJECTED: {reason}");
            } else {
                eprintln!("Unexpected response from receiver: {message}");
            }

            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("Could not confirm transfer completion: {error}");
            eprintln!("The file may have arrived, but its final status is unknown.");
            std::process::exit(1);
        }
    }
}

fn get_file_path() -> Result<PathBuf, String> {
    let mut args = env::args_os();
    let _program = args.next();

    match (args.next(), args.next()) {
        (Some(path), None) => Ok(PathBuf::from(path)),
        (None, _) => Err("Error: Please provide a file path.".to_string()),
        (Some(_), Some(_)) => Err(
            "Error: Please provide exactly one file path. Put paths containing spaces in quotes."
                .to_string(),
        ),
    }
}

fn load_phone_signing_key() -> ed25519_dalek::SigningKey {
    let key_bytes = std::fs::read("phone_device_key.bin").expect("Failed to read phone device key");

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .expect("Phone device key must contain exactly 32 bytes");

    ed25519_dalek::SigningKey::from_bytes(&key_array)
}
