use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

fn main() {
    // OsRng fournit des nombres aléatoires sûrs à partir du système.
    let mut rng = OsRng;

    // Vladimir crée une clé privée RSA de 2048 bits.
    let cle_privee =
        RsaPrivateKey::new(&mut rng, 2048).expect("Impossible de générer la clé privée");
    let cle_publique = RsaPublicKey::from(&cle_privee);

    let message = b"Hello Vladimir let's play GTA VI";

    // OAEP ajoute un aléa : le même message donnera un chiffré différent.
    // L'objet OAEP doit être recréé car la bibliothèque le consomme à chaque appel.
    let chiffre_1 = cle_publique
        .encrypt(&mut rng, Oaep::new::<Sha256>(), message)
        .expect("Le chiffrement a échoué");

    let chiffre_2 = cle_publique
        .encrypt(&mut rng, Oaep::new::<Sha256>(), message)
        .expect("Le second chiffrement a échoué");

    let dechiffre = cle_privee
        .decrypt(Oaep::new::<Sha256>(), &chiffre_1)
        .expect("Le déchiffrement a échoué");

    println!("Message retrouvé : {}", String::from_utf8_lossy(&dechiffre));
    println!("Taille du messages chiffré : {} octets", chiffre_1.len());
    println!(
        "Deux chiffrements du même message sont différents : {}",
        chiffre_1 != chiffre_2
    );

    // Une autre clé privée ne doit pas pouvoir déchiffrer le message.
    let autre_cle =
        RsaPrivateKey::new(&mut rng, 2048).expect("Impossible de générer la seconde clé");
    let resultat_autre_cle = autre_cle.decrypt(Oaep::new::<Sha256>(), &chiffre_1);
    println!(
        "Déchiffrement avec une autre clé refusé : {}",
        resultat_autre_cle.is_err()
    );

    // Avec RSA-2048 et OAEP/SHA-256, 200 octets dépassent la taille autorisée.
    let message_trop_long = vec![b'A'; 200];
    let resultat_trop_long =
        cle_publique.encrypt(&mut rng, Oaep::new::<Sha256>(), &message_trop_long);
    println!(
        "Message de 200 octets refusé : {}",
        resultat_trop_long.is_err()
    );
}
