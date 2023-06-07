use base64::{engine::general_purpose::STANDARD as b64, DecodeError, Engine};
use ethers::utils::{hex, keccak256};

/// Ethereum addresses are created by taking the keccak256 hash of the last 20 bytes
/// of the public key and representing it as a hexadecimal number.
fn convert(public_key: String) -> Result<String, DecodeError> {
    let bytes = b64.decode(public_key)?;
    let hash = keccak256(bytes)[12..].to_vec();
    let mut hex = hex::encode(hash);
    hex.insert_str(0, "0x");
    Ok(hex)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("\nUsage:\tad64 BASE64_PUBLIC_KEY\n");
        return;
    }
    let public_key = args[1].clone();
    let hex = match convert(public_key) {
        Ok(hex) => hex,
        Err(err) => {
            println!("Error decoding the base64 string: {}", err);
            return;
        }
    };
    println!("\nAddress: {}\n", hex);
}

#[test]
fn test_ok() {
    let public_key =
        "qpMfXuWHNScIIbNyKGbYiC0ZSJCVMs+KwrPvFEroBDNj0dNyi0nxDHzXjDgonIASR3Rzh587UxafKmd7f77Qxw==";
    let hex = convert(public_key.to_string()).unwrap();
    let expected = "0xe16c1623c1aa7d919cd2241d8b36d9e79c1be2a2".to_string();
    assert_eq!(hex, expected);
}
