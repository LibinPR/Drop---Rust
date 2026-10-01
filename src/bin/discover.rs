use std::net::UdpSocket;
use std::time::Duration;

const DISCOVERY_PORT: u16 = 9001;

const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";

fn main() {
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

    println!("Searching for Drop devices...\n");

    let mut buffer = [0u8; 1024];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((bytes_received, sender_address)) => {
                let message =
                    String::from_utf8_lossy(&buffer[..bytes_received]);

                let parts: Vec<&str> =
                    message.split('|').collect();

                if parts.len() == 4
                    && parts[0] == "DROP_HERE"
                {
                    let device_id = parts[1];
                    let device_name = parts[2];
                    let transfer_port = parts[3];

                    println!("Found Drop device:");
                    println!("  Name: {}", device_name);
                    println!("  ID: {}", device_id);
                    println!(
                        "  IP: {}",
                        sender_address.ip()
                    );
                    println!(
                        "  Port: {}",
                        transfer_port
                    );
                    println!();
                }
            }

            Err(_) => {
                println!("Discovery finished.");
                break;
            }
        }
    }
}