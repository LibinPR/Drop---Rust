use std::fs;
use std::path::Path;

const TRUSTED_DEVICES_FILE: &str = "trusted_devices.txt";

pub fn load_trusted_devices() -> Vec<String> {
    if !Path::new(TRUSTED_DEVICES_FILE).exists() {
        return Vec::new();
    }

    let contents =
        fs::read_to_string(TRUSTED_DEVICES_FILE)
            .expect("Failed to read trusted devices");

    contents
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

pub fn is_trusted(
    device_id: &str,
) -> bool {
    let devices =
        load_trusted_devices();

    devices
        .iter()
        .any(|id| id == device_id)
}

pub fn add_trusted_device(
    device_id: &str,
) {
    if is_trusted(device_id) {
        return;
    }

    let mut devices =
        load_trusted_devices();

    devices.push(device_id.to_string());

    let contents =
        devices.join("\n");

    fs::write(
        TRUSTED_DEVICES_FILE,
        contents,
    )
    .expect("Failed to save trusted device");

    println!(
        "Trusted device saved: {}",
        device_id
    );
}