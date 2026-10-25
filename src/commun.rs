#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

pub const MOT_DE_PASSE: &str = "mot-de-passe-du-tp";

// AAD signifie "Additional Authenticated Data".
// Cette valeur doit être strictement identique chez Donald et Vladimir.
pub const AAD: &[u8] = b"transfert-document:v1";

// Les données binaires sont stockées en Base64 dans les champs String.
#[derive(Serialize, Deserialize)]
pub struct Enveloppe {
    pub version: u8,
    pub id: String,
    pub expediteur: String,
    pub destinataire: String,
    pub cle_aes_chiffree: String,
    pub nonce: String,
    pub contenu_chiffre: String,
    pub signature: String,
}

// La signature est exclue de cette structure pour éviter de se signer elle-même.
#[derive(Serialize)]
struct DonneesSignees<'a> {
    version: u8,
    id: &'a str,
    expediteur: &'a str,
    destinataire: &'a str,
    cle_aes_chiffree: &'a str,
    nonce: &'a str,
    contenu_chiffre: &'a str,
}

impl Enveloppe {
    pub fn donnees_signees(&self) -> Vec<u8> {
        let donnees = DonneesSignees {
            version: self.version,
            id: &self.id,
            expediteur: &self.expediteur,
            destinataire: &self.destinataire,
            cle_aes_chiffree: &self.cle_aes_chiffree,
            nonce: &self.nonce,
            contenu_chiffre: &self.contenu_chiffre,
        };

        // Une structure Rust garde toujours le même ordre de champs dans le JSON.
        serde_json::to_vec(&donnees).expect("Impossible de préparer les données à signer")
    }
}

pub fn vers_base64(donnees: &[u8]) -> String {
    // Base64 facilite le stockage dans JSON, mais ne chiffre rien.
    STANDARD.encode(donnees)
}

pub fn depuis_base64(texte: &str) -> Vec<u8> {
    STANDARD.decode(texte).expect("Base64 invalide")
}
