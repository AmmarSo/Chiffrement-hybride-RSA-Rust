mod commun;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng as AesRng, Payload},
};
use commun::{AAD, Enveloppe, MOT_DE_PASSE, vers_base64};
use rand::{RngCore, rngs::OsRng};
use rsa::{
    Oaep, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use sha2::{Digest, Sha256};
use std::fs;

fn main() {
    // Donald charge sa clé privée pour signer et la clé publique du destinataire.
    let privee_pem = fs::read_to_string("cles/donald_privee.pem")
        .expect("Lancez d'abord : cargo run --bin generer_cles");
    let publique_pem = fs::read_to_string("cles/vladimir_publique.pem")
        .expect("Clé publique de Vladimir introuvable");

    let cle_privee_donald = RsaPrivateKey::from_pkcs8_encrypted_pem(&privee_pem, MOT_DE_PASSE)
        .expect("Mot de passe incorrect pour la clé de Donald");
    let cle_publique_vladimir = RsaPublicKey::from_public_key_pem(&publique_pem)
        .expect("Clé publique de Vladimir invalide");

    let contenu = fs::read("../message.txt").expect("message.txt est introuvable");

    // Une nouvelle clé AES et un nouveau nonce sont créés pour cette enveloppe.
    let cle_aes = Aes256Gcm::generate_key(AesRng);
    let nonce = Aes256Gcm::generate_nonce(&mut AesRng);

    // AES-GCM chiffre le document et ajoute un tag contre les modifications.
    let contenu_chiffre = Aes256Gcm::new(&cle_aes)
        .encrypt(
            &nonce,
            Payload {
                msg: &contenu,
                aad: AAD,
            },
        )
        .expect("Chiffrement AES impossible");

    let mut rng = OsRng;

    // OAEP protège la clé AES avec la clé publique de Vladimir.
    let cle_aes_chiffree = cle_publique_vladimir
        .encrypt(&mut rng, Oaep::new::<Sha256>(), cle_aes.as_slice())
        .expect("Chiffrement RSA impossible");

    // Cet identifiant unique permettra à Vladimir de détecter un rejeu.
    let mut id_aleatoire = [0_u8; 16];
    rng.fill_bytes(&mut id_aleatoire);

    let mut enveloppe = Enveloppe {
        version: 1,
        id: vers_base64(&id_aleatoire),
        expediteur: "Donald".to_string(),
        destinataire: "Vladimir".to_string(),
        cle_aes_chiffree: vers_base64(&cle_aes_chiffree),
        nonce: vers_base64(nonce.as_slice()),
        contenu_chiffre: vers_base64(&contenu_chiffre),
        signature: String::new(),
    };

    // PSS signe l'empreinte des champs importants, sans le champ signature.
    let empreinte = Sha256::digest(enveloppe.donnees_signees());
    let signature = cle_privee_donald
        .sign_with_rng(&mut rng, Pss::new_with_salt::<Sha256>(32), &empreinte)
        .expect("Signature RSA-PSS impossible");
    enveloppe.signature = vers_base64(&signature);

    let json = serde_json::to_string_pretty(&enveloppe).expect("Création du JSON impossible");
    fs::write("enveloppe.json", json).expect("Écriture de enveloppe.json impossible");

    println!("Enveloppe créée et signée dans enveloppe.json");
    println!("Identifiant : {}", enveloppe.id);
}
