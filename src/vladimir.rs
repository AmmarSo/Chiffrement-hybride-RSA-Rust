mod commun;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use commun::{AAD, Enveloppe, MOT_DE_PASSE, depuis_base64};
use rsa::{
    Oaep, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use sha2::{Digest, Sha256};
use std::fs;

fn main() {
    let json = fs::read_to_string("enveloppe.json").expect("enveloppe.json est introuvable");
    let enveloppe: Enveloppe = serde_json::from_str(&json).expect("JSON invalide");

    // La liste locale contient les identifiants déjà acceptés.
    let deja_recus = fs::read_to_string("identifiants_acceptes.txt").unwrap_or_default();
    if deja_recus.lines().any(|id| id == enveloppe.id) {
        println!("Enveloppe refusée : cet identifiant a déjà été accepté");
        return;
    }

    let publique_pem =
        fs::read_to_string("cles/donald_publique.pem").expect("Clé publique de Donald introuvable");
    let cle_publique_donald =
        RsaPublicKey::from_public_key_pem(&publique_pem).expect("Clé publique de Donald invalide");

    // Vladimir vérifie la signature avec la clé publique connue de Donald.
    let empreinte = Sha256::digest(enveloppe.donnees_signees());
    let signature = depuis_base64(&enveloppe.signature);
    if cle_publique_donald
        .verify(Pss::new_with_salt::<Sha256>(32), &empreinte, &signature)
        .is_err()
    {
        println!("Enveloppe refusée : signature invalide");
        return;
    }
    println!("Signature de Donald valide");

    let privee_pem =
        fs::read_to_string("cles/vladimir_privee.pem").expect("Clé privée de Vladimir introuvable");
    let cle_privee_vladimir = RsaPrivateKey::from_pkcs8_encrypted_pem(&privee_pem, MOT_DE_PASSE)
        .expect("Mot de passe incorrect pour la clé de Vladimir");

    // Base64 est retiré avant les opérations cryptographiques.
    let cle_aes_chiffree = depuis_base64(&enveloppe.cle_aes_chiffree);
    let cle_aes = cle_privee_vladimir
        .decrypt(Oaep::new::<Sha256>(), &cle_aes_chiffree)
        .expect("Impossible de retrouver la clé AES");

    let nonce = depuis_base64(&enveloppe.nonce);
    let contenu_chiffre = depuis_base64(&enveloppe.contenu_chiffre);
    if nonce.len() != 12 {
        println!("Enveloppe refusée : taille du nonce incorrecte");
        return;
    }

    let aes = Aes256Gcm::new_from_slice(&cle_aes).expect("Clé AES invalide");
    // decrypt vérifie aussi le tag AES-GCM et les AAD.
    let resultat = aes.decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: &contenu_chiffre,
            aad: AAD,
        },
    );

    let contenu = match resultat {
        Ok(contenu) => contenu,
        Err(_) => {
            println!("Enveloppe refusée : contenu ou tag AES-GCM invalide");
            return;
        }
    };

    fs::write("message_dechiffre_avance.txt", contenu)
        .expect("Impossible d'écrire le fichier déchiffré");

    // L'identifiant n'est mémorisé qu'après toutes les vérifications.
    let nouvelle_liste = format!("{deja_recus}{}\n", enveloppe.id);
    fs::write("identifiants_acceptes.txt", nouvelle_liste)
        .expect("Impossible d'enregistrer l'identifiant");

    println!("Document accepté et écrit dans message_dechiffre_avance.txt");
}
