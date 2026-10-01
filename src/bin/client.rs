use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek ,Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use drop::protocol::{send_header, TransferHeader};

fn main() {
    let filename = "big.txt";

    let mut file = File::open(filename).unwrap();

    let file_size = file.metadata().unwrap().len();

    println!("File: {}", filename);
    println!("File size: {} bytes", file_size);

    // Calculate SHA-256 checksum.
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

    // Go back to the beginning of the file.
    file.rewind().unwrap();

    let mut stream = TcpStream::connect("192.168.1.5:9000").unwrap();

    // Create a unique transfer ID.
    let transfer_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let header = TransferHeader {
        transfer_id,
        filename: filename.to_string(),
        file_size,
        checksum: checksum.into(),
    };

    // Send the header.
    send_header(&mut stream, &header).unwrap();

    println!("Transfer ID: {}", transfer_id);
    println!("Header sent!");

    // Send the file data.
    let mut sent = 0u64;

    while sent < file_size {
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            break;
        }

        stream.write_all(&buffer[..bytes_read]).unwrap();

        sent += bytes_read as u64;

        println!("Sent {} / {} bytes", sent, file_size);
    }

    if sent == file_size {
        println!("File sent successfully!");
    } else {
        println!(
            "Transfer incomplete: sent {} / {} bytes",
            sent, file_size
        );
    }
}