fn main() {
    println!("TP chiffrement hybride et RSA");
    println!();
    println!("cargo run --bin rsa_simple  # RSA avec de petits nombres");
    println!("cargo run --bin rsa_oaep    # RSA-OAEP avec une bibliothèque");
    println!("cargo run --bin hybride     # RSA-OAEP + AES-256-GCM");
    println!();
    println!("Mode avancé :");
    println!("cargo run --bin generer_cles");
    println!("cargo run --bin donald");
    println!("cargo run --bin vladimir");
}
