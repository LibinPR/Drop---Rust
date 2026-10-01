use rand::Rng;
use std::fs;
use std::net::UdpSocket;
use std::path::Path;

const DISCOVERY_PORT: u16 = 9001;
const TRANSFER_PORT: u16 = 9000;

const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";

const DEVICE_ID_FILE: &str = "device_id.txt";

pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
}

pub fn load_or_create_device_identity() -> DeviceIdentity {
    let device_id = if Path::new(DEVICE_ID_FILE).exists() {
        println!("Loading existing device ID.");

        fs::read_to_string(DEVICE_ID_FILE)
            .unwrap()
            .trim()
            .to_string()
    } else {
        println!("Creating new device ID.");

        let mut rng = rand::rng();

        let random_id: u128 = rng.random();

        let device_id = format!("{:032x}", random_id);

        fs::write(DEVICE_ID_FILE, &device_id).unwrap();

        device_id
    };

    DeviceIdentity {
        device_id,
        device_name: "Libin-PC".to_string(),
    }
}

pub fn run_server(identity: DeviceIdentity) {
    let socket =
        UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).unwrap();

    println!(
        "Discovery server listening on UDP port {}",
        DISCOVERY_PORT
    );

    println!("Device name: {}", identity.device_name);
    println!("Device ID: {}", identity.device_id);

    let mut buffer = [0u8; 1024];

    loop {
        let (bytes_received, sender_address) =
            socket.recv_from(&mut buffer).unwrap();

        let message = &buffer[..bytes_received];

        if message == DISCOVERY_MESSAGE {
            println!(
                "Discovery request from {}",
                sender_address
            );

            let response = format!(
                "DROP_HERE|{}|{}|{}",
                identity.device_id,
                identity.device_name,
                TRANSFER_PORT
            );

            socket
                .send_to(response.as_bytes(), sender_address)
                .unwrap();

            println!(
                "Discovery response sent to {}",
                sender_address
            );
        }
    }
}