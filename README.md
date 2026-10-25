# TP chiffrement hybride et RSA en Rust

Le projet contient une petite démonstration par partie :

- `rsa_simple.rs` : calcul RSA avec les petits nombres de l'énoncé ;
- `rsa_oaep.rs` : chiffrement RSA-OAEP avec SHA-256 ;
- `hybride.rs` : chiffrement d'un fichier avec AES-256-GCM et protection de la clé AES avec RSA-OAEP ;
- `donald.rs` et `vladimir.rs` : mode avancé avec JSON, Base64, clés PEM, signature RSA-PSS et contrôle du rejeu.

## Lancer les parties obligatoires

Depuis la racine du projet :

```powershell
cargo run --bin rsa_simple
cargo run --bin rsa_oaep
cargo run --bin hybride
```

Le dernier programme lit `message.txt` et crée `message_dechiffre.txt`.

## Lancer le mode avancé

Les commandes doivent être exécutées dans cet ordre :

```powershell
cargo run --bin generer_cles
cargo run --bin donald
cargo run --bin vladimir
```

Le mot de passe des clés privées est `mot-de-passe-du-tp`. Il est écrit dans le code uniquement pour simplifier ce TP.

Les fichiers importants sont :

- `cles/` : clés RSA privées et publiques ;
- `enveloppe.json` : données envoyées par Donald ;
- `message_dechiffre_avance.txt` : document retrouvé par Vladimir ;
- `identifiants_acceptes.txt` : identifiants déjà reçus, utilisés contre le rejeu.

Si `vladimir` est lancé une deuxième fois sans recréer l'enveloppe, le message est refusé comme rejeu. Pour créer une nouvelle enveloppe, relancer seulement `donald`.

Pour recommencer avec de nouvelles clés, supprimer volontairement le dossier `cles`, puis relancer `generer_cles`. Une ancienne enveloppe ne pourra plus être déchiffrée avec les nouvelles clés.

## Bibliothèques utilisées

- `rsa` pour RSA-OAEP, RSA-PSS et les fichiers PEM ;
- `aes-gcm` pour AES-256-GCM ;
- `sha2` pour SHA-256 ;
- `serde_json` et `base64` pour l'enveloppe JSON.
