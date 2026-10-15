use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek};
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use drop::protocol::{TransferHeader, send_header};
use drop::secure_channel;

const DISCOVERY_PORT: u16 = 9001;
const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";
const CHUNK_SIZE: usize = 32 * 1024;

fn main() {
    // Discover a Drop device on the local network.
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

    let mut buffer = [0u8; 1024];

    let (device_ip, device_port, device_id, device_name) = loop {
        match socket.recv_from(&mut buffer) {
            Ok((bytes_received, sender_address)) => {
                let message = String::from_utf8_lossy(&buffer[..bytes_received]);
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
                println!("Discovery failed or timed out: {error}");
                return;
            }
        }
    };

    println!("Found device: {device_name}");
    println!("Device ID: {device_id}");
    println!("Connecting to {device_ip}:{device_port}...");

    let stream = match std::net::TcpStream::connect((device_ip, device_port)) {
        Ok(stream) => stream,
        Err(error) => {
            println!("Connection failed: {error}");
            return;
        }
    };

    // This is the persistent identity key for the phone/test device.
    let signing_key = load_phone_signing_key();

    // Establish encryption and verify the PC's identity against discovery.
    let mut channel = match secure_channel::connect_client(stream, &signing_key, &device_id) {
        Ok(channel) => channel,
        Err(error) => {
            println!("Secure connection failed: {error}");
            return;
        }
    };

    println!("Secure connection established; both device identities verified.");

    let filename = "big.txt";

    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(error) => {
            println!("Failed to open {filename}: {error}");
            return;
        }
    };

    let file_size = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            println!("Failed to read file metadata: {error}");
            return;
        }
    };

    println!("File: {filename}");
    println!("File size: {file_size} bytes");

    // Calculate the checksum before sending.
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(error) => {
                println!("Failed to read file: {error}");
                return;
            }
        };

        hasher.update(&buffer[..bytes_read]);
    }

    let checksum = hasher.finalize();

    if let Err(error) = file.rewind() {
        println!("Failed to rewind file: {error}");
        return;
    }

    let transfer_id = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(error) => {
            println!("System clock error: {error}");
            return;
        }
    };

    let header = TransferHeader {
        transfer_id,
        filename: filename.to_string(),
        file_size,
        checksum: checksum.into(),
    };

    // Serialize the header, then send it through the encrypted channel.
    let mut header_bytes = Vec::new();

    if let Err(error) = send_header(&mut header_bytes, &header) {
        println!("Failed to prepare file header: {error}");
        return;
    }

    if let Err(error) = channel.send(&header_bytes) {
        println!("Failed to send encrypted header: {error}");
        return;
    }

    let mut sent = 0u64;

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(error) => {
                println!("Failed to read file: {error}");
                return;
            }
        };

        // Each chunk becomes a separately authenticated encrypted message.
        if let Err(error) = channel.send(&buffer[..bytes_read]) {
            println!("Failed to send encrypted file data: {error}");
            return;
        }

        sent += bytes_read as u64;
        println!("Sent {sent} / {file_size} bytes");
    }

    println!("File data sent. The receiver verifies SHA-256 before saving it.");
}

fn load_phone_signing_key() -> ed25519_dalek::SigningKey {
    let key_bytes = std::fs::read("phone_device_key.bin").expect("Failed to read phone device key");

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .expect("Phone device key must contain exactly 32 bytes");

    ed25519_dalek::SigningKey::from_bytes(&key_array)
}
