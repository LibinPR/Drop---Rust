use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use drop::protocol::receive_header;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:9000").unwrap();

    println!("Server is listening on 127.0.0.1:9000");

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        thread::spawn(|| {
            handle_client(stream);
        });
    }
}

fn handle_client(mut stream: std::net::TcpStream) {
    // Receive the transfer header.
    let header = receive_header(&mut stream).unwrap();

    println!("Transfer ID: {}", header.transfer_id);
    println!("Filename: {}", header.filename);
    println!("File size: {} bytes", header.file_size);

    // Create a unique destination filename.
    let path = format!(
        "received/{}_{}",
        header.transfer_id,
        header.filename
    );

    let mut file = File::create(&path).unwrap();

    // Receive the file in chunks.
    let mut buffer = [0u8; 1024];

    let mut received = 0u64;

    while received < header.file_size {
        let bytes_read = stream.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read]).unwrap();

        received += bytes_read as u64;

        println!(
            "Received {} / {} bytes",
            received,
            header.file_size
        );
    }

    if received == header.file_size {
        println!("File saved as {}", path);
    } else {
        println!(
            "Transfer incomplete: received {} / {} bytes",
            received,
            header.file_size
        );
    }
}