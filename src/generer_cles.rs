mod commun;

use commun::MOT_DE_PASSE;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey,pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use std::fs;
use std::path::Path;

fn enregistrer_paire(nom: &str, rng: &mut OsRng) {
    println!("Génération de la paire de clés de {nom}...");

    let cle_privee = RsaPrivateKey::new(rng, 3072).expect("Génération RSA impossible");
    let cle_publique = RsaPublicKey::from(&cle_privee);

    // La clé privée est protégée par mot de passe, la clé publique ne l'est pas.
    let privee_pem = cle_privee
        .to_pkcs8_encrypted_pem(rng, MOT_DE_PASSE, LineEnding::LF)
        .expect("Impossible de protéger la clé privée");
    let publique_pem = cle_publique
        .to_public_key_pem(LineEnding::LF)
        .expect("Impossible d'exporter la clé publique");

    fs::write(format!("cles/{nom}_privee.pem"), privee_pem.as_bytes())
        .expect("Impossible d'écrire la clé privée");
    fs::write(format!("cles/{nom}_publique.pem"), publique_pem)
        .expect("Impossible d'écrire la clé publique");

    let mauvais_mot_de_passe =
        RsaPrivateKey::from_pkcs8_encrypted_pem(&privee_pem, "mauvais-mot-de-passe");
    println!(
        "Mot de passe incorrect refusé pour {nom} : {}",
        mauvais_mot_de_passe.is_err()
    );
}

fn main() {
    if Path::new("cles/donald_privee.pem").exists()
        || Path::new("cles/vladimir_privee.pem").exists()
    {
        println!("Des clés existent déjà : elles ne sont pas remplacées.");
        return;
    }

    fs::create_dir_all("cles").expect("Impossible de créer le dossier cles");

    let mut rng = OsRng;
    enregistrer_paire("donald", &mut rng);
    enregistrer_paire("vladimir", &mut rng);

    println!("Clés enregistrées dans le dossier cles/");
    println!("Mot de passe de démonstration : {MOT_DE_PASSE}");
}
