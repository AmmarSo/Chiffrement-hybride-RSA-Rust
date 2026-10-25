use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng as AesRng, Payload},
};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::fs;

// AAD = données associées authentifiées : elles ne sont pas chiffrées,
// mais AES-GCM détecte si elles sont modifiées.
const AAD: &[u8] = b"version=1;sender=Donald;recipient=Vladimir";

fn main() {
    // Vladimir crée sa paire de clés RSA.
    let mut rng = OsRng;
    let cle_privee_vladimir =
        RsaPrivateKey::new(&mut rng, 3072).expect("Impossible de générer la clé RSA");
    let cle_publique_vladimir = RsaPublicKey::from(&cle_privee_vladimir);

    // ----- Côté Donald -----
    let contenu = fs::read("../message.txt").expect("Impossible de lire message.txt");

    // AES-256 utilise une clé aléatoire de 32 octets.
    let cle_aes = Aes256Gcm::generate_key(AesRng);

    // Le nonce est public, mais doit être unique pour chaque chiffrement avec cette clé.
    let nonce = Aes256Gcm::generate_nonce(&mut AesRng);
    let aes_donald = Aes256Gcm::new(&cle_aes);

    // Le résultat contient le texte chiffré suivi du tag d'authentification.
    let contenu_chiffre = aes_donald
        .encrypt(
            &nonce,
            Payload {
                msg: &contenu,
                aad: AAD,
            },
        )
        .expect("Le chiffrement AES a échoué");

    // RSA chiffre seulement la petite clé AES, pas le fichier entier.
    let cle_aes_chiffree = cle_publique_vladimir
        .encrypt(&mut rng, Oaep::new::<Sha256>(), cle_aes.as_slice())
        .expect("Le chiffrement de la clé AES a échoué");

    // Ces trois éléments peuvent être envoyés à Vladimir.
    println!("Nonce : {} octets", nonce.len());
    println!("Contenu chiffré + tag : {} octets", contenu_chiffre.len());
    println!("Clé AES chiffrée : {} octets", cle_aes_chiffree.len());

    // ----- Côté Vladimir -----
    // Seule la clé privée de Vladimir permet de retrouver la clé AES.
    let cle_aes_retrouvee = cle_privee_vladimir
        .decrypt(Oaep::new::<Sha256>(), &cle_aes_chiffree)
        .expect("Impossible de retrouver la clé AES");

    let aes_vladimir = Aes256Gcm::new_from_slice(&cle_aes_retrouvee)
        .expect("La clé AES retrouvée n'a pas la bonne taille");

    let contenu_retrouve = aes_vladimir
        .decrypt(
            Nonce::from_slice(nonce.as_slice()),
            Payload {
                msg: &contenu_chiffre,
                aad: AAD,
            },
        )
        .expect("Le contenu ou son tag a été modifié");

    fs::write("message_dechiffre.txt", &contenu_retrouve)
        .expect("Impossible d'écrire message_dechiffre.txt");

    println!("Fichier retrouvé : {}", contenu_retrouve == contenu);

    // Test demandé : une modification d'un octet doit être détectée.
    let mut contenu_modifie = contenu_chiffre.clone();
    contenu_modifie[0] ^= 1;

    let resultat_modifie = aes_vladimir.decrypt(
        Nonce::from_slice(nonce.as_slice()),
        Payload {
            msg: &contenu_modifie,
            aad: AAD,
        },
    );

    println!(
        "Contenu modifié détecté par AES-GCM : {}",
        resultat_modifie.is_err()
    );
}
