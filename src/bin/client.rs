use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

use drop::protocol::{send_header, TransferHeader};

fn main() {
    let filename = "big.txt";

    let mut file = File::open(filename).unwrap();

    let file_size = file.metadata().unwrap().len();

    println!("File: {}", filename);
    println!("File size: {} bytes", file_size);

    let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();

    // Create a transfer ID.
    // For now, we are using 1 for testing.
    let transfer_id = 1;

    let header = TransferHeader {
        transfer_id,
        filename: filename.to_string(),
        file_size,
    };

    // Send the header.
    send_header(&mut stream, &header).unwrap();

    println!("Transfer ID: {}", transfer_id);
    println!("Header sent!");

    // Send the file data in chunks.
    let mut buffer = [0u8; 1024];

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