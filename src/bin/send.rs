use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::{
    Arc,
    atomic::{AtomicBool , Ordering},
};

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
    println!("File size: {}", format_bytes(file_size));

    // First pass: calculate the expected checksum.
    println!("Preparing file checksum...");

    let mut expected_hasher = Sha256::new();
    let mut buffer = [0u8; CHUNK_SIZE];

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_flag = Arc::clone(&cancelled);

    ctrlc::set_handler(move || {
        cancel_flag.store(true, Ordering::SeqCst);
    })
    .expect("Failed to register Ctrl+C handler");

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
    let socket = UdpSocket::bind("0.0.0.0:0")
        .expect("Failed to create discovery socket");

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

    let mut channel =
        match secure_channel::connect_client(stream, &signing_key, &device_id) {
            Ok(channel) => channel,
            Err(error) => {
                eprintln!("Secure connection failed: {error}");
                std::process::exit(1);
            }
        };

    println!("Secure connection established; both device identities verified.");

    
    let checksum_bytes = expected_checksum.as_slice();
    let transfer_id = u64::from_be_bytes(
        checksum_bytes[..8]
            .try_into()
            .expect("SHA-256 checksum must contain at least 8 bytes"),
    );


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
    
    let resume_response = match channel.receive() {
        Ok(response) if response.len() == 8 => response,
        Ok(_) => {
            eprintln!("Receiver returned an invalid resume offset.");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("Could not negotiate resume position: {error}");
            std::process::exit(1);
        }
    };

    let resume_offset = u64::from_be_bytes(
        resume_response
            .as_slice()
            .try_into()
            .expect("Resume offset must contain 8 bytes"),
    );

    if resume_offset > file_size {
        eprintln!("Receiver's resume offset exceeds the source file size.");
        std::process::exit(1);
    }

    println!("Resuming from {} of {}.", format_bytes(resume_offset), format_bytes(file_size));

    if let Err(error) = file.rewind() {
        eprintln!("Failed to rewind source file: {error}");
        std::process::exit(1);
    }

    let mut sent_hasher = Sha256::new();
    let mut prefix_remaining = resume_offset;

    while prefix_remaining > 0 {
        let amount = prefix_remaining.min(buffer.len() as u64) as usize;
        let bytes_read = match file.read(&mut buffer[..amount]) {
            Ok(0) => {
                eprintln!("Source file ended before the resume offset.");
                std::process::exit(1);
            }
            Ok(count) => count,
            Err(error) => {
                eprintln!("Could not verify the resumed prefix: {error}");
                std::process::exit(1);
            }
        };

        sent_hasher.update(&buffer[..bytes_read]);
        prefix_remaining -= bytes_read as u64;
    }

    if let Err(error) = file.seek(SeekFrom::Start(resume_offset)) {
        eprintln!("Could not seek to resume position: {error}");
        std::process::exit(1);
    }




    // Second pass: hash and send exactly the bytes being transmitted.
    let mut sent = resume_offset;
    let transfer_started = Instant::now();

    println!("Sending file...");

    loop {
        if cancelled.load(Ordering::SeqCst) {
            println!("\nTransfer cancelled. Closing connection...");
            let _ = channel.shutdown();
            std::process::exit(130);
        }

        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("\nFailed to read file while sending: {error}");
                eprintln!("The transfer may be incomplete.");
                std::process::exit(1);
            }
        };

        sent_hasher.update(&buffer[..bytes_read]);

        if let Err(error) = channel.send(&buffer[..bytes_read]) {
            eprintln!("\nFailed to send encrypted file data: {error}");
            std::process::exit(1);
        }

        sent += bytes_read as u64;

        show_progress(sent, file_size, transfer_started);
    }

    // Ensure even an empty file displays a completed progress line.
    show_progress(sent, file_size, transfer_started);
    println!();

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
            if sent_checksum.as_slice() == expected_checksum.as_slice()
                && sent == file_size
            {
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

fn show_progress(sent: u64, total: u64, started: Instant) {
    let percent = if total == 0 {
        100
    } else {
        ((sent as f64 / total as f64) * 100.0).round() as u64
    };

    let elapsed = started.elapsed().as_secs_f64();
    let speed = if elapsed > 0.0 {
        sent as f64 / elapsed
    } else {
        0.0
    };

    let eta = if total <= sent {
        "00:00".to_string()
    } else if speed > 0.0 {
        format_duration(((total - sent) as f64 / speed).ceil() as u64)
    } else {
        "--:--".to_string()
    };

    let bar_width = 24usize;
    let filled = ((percent as usize * bar_width) / 100).min(bar_width);
    let bar = format!(
        "{}{}",
        "#".repeat(filled),
        "-".repeat(bar_width - filled)
    );

    print!(
        "\r[{bar}] {percent:3}% | {} / {} | {} | ETA {eta}",
        format_bytes(sent),
        format_bytes(total),
        format_bytes(speed as u64),
    );

    let _ = io::stdout().flush();
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    let mut value = bytes as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
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
    let key_bytes =
        std::fs::read("phone_device_key.bin").expect("Failed to read phone device key");

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .expect("Phone device key must contain exactly 32 bytes");

    ed25519_dalek::SigningKey::from_bytes(&key_array)
}
