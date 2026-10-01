use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use drop::protocol::{send_header, TransferHeader};

const DISCOVERY_PORT: u16 = 9001;
const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";

fn main() {
    // --------------------------------------------------
    // 1. Discover a Drop device
    // --------------------------------------------------

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

    socket.set_broadcast(true).unwrap();

    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let broadcast_address =
        format!("255.255.255.255:{}", DISCOVERY_PORT);

    socket
        .send_to(DISCOVERY_MESSAGE, broadcast_address)
        .unwrap();

    println!("Searching for Drop devices...");

    let mut buffer = [0u8; 1024];

    let (bytes_received, sender_address) =
        socket.recv_from(&mut buffer).unwrap();

    let message =
        String::from_utf8_lossy(&buffer[..bytes_received]);

    println!("Found device at {}", sender_address.ip());
    println!("Response: {}", message);

    // --------------------------------------------------
    // 2. Parse the discovery response
    // --------------------------------------------------

    let parts: Vec<&str> = message.split('|').collect();

    if parts.len() != 3 || parts[0] != "DROP_HERE" {
        println!("Invalid discovery response.");
        return;
    }

    let device_name = parts[1];

    let transfer_port: u16 = match parts[2].parse() {
        Ok(port) => port,
        Err(_) => {
            println!("Invalid transfer port.");
            return;
        }
    };

    println!("Device name: {}", device_name);
    println!("Transfer port: {}", transfer_port);

    // --------------------------------------------------
    // 3. Connect to the discovered device
    // --------------------------------------------------

    let server_address =
        format!("{}:{}", sender_address.ip(), transfer_port);

    println!("Connecting to {}...", server_address);

    let mut stream = TcpStream::connect(&server_address).unwrap();

    println!("Connected!");

    // --------------------------------------------------
    // 4. Open the file
    // --------------------------------------------------

    let filename = "big.txt";

    let mut file = File::open(filename).unwrap();

    let file_size = file.metadata().unwrap().len();

    println!("File: {}", filename);
    println!("File size: {} bytes", file_size);

    // --------------------------------------------------
    // 5. Calculate SHA-256 checksum
    // --------------------------------------------------

    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 1024];

    loop {
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let checksum = hasher.finalize();

    println!("Checksum calculated.");

    // Go back to the beginning.
    file.rewind().unwrap();

    // --------------------------------------------------
    // 6. Create transfer ID
    // --------------------------------------------------

    let transfer_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // --------------------------------------------------
    // 7. Create and send transfer header
    // --------------------------------------------------

    let header = TransferHeader {
        transfer_id,
        filename: filename.to_string(),
        file_size,
        checksum: checksum.into(),
    };

    send_header(&mut stream, &header).unwrap();

    println!("Transfer ID: {}", transfer_id);
    println!("Header sent!");

    // --------------------------------------------------
    // 8. Send file
    // --------------------------------------------------

    let mut sent = 0u64;

    while sent < file_size {
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            break;
        }

        stream.write_all(&buffer[..bytes_read]).unwrap();

        sent += bytes_read as u64;

        println!(
            "Sent {} / {} bytes",
            sent,
            file_size
        );
    }

    // --------------------------------------------------
    // 9. Finish
    // --------------------------------------------------

    if sent == file_size {
        println!("Transfer complete!");
    } else {
        println!(
            "Transfer incomplete: sent {} / {} bytes",
            sent,
            file_size
        );
    }
}