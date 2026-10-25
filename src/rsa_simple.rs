/// Calcule (base^exposant) mod modulo par exponentiation rapide.
fn puissance_modulaire(mut base: u64, mut exposant: u64, modulo: u64) -> u64 {
    let mut resultat = 1_u64;
    base %= modulo;

    while exposant > 0 {
        if exposant % 2 == 1 {
            resultat = (resultat * base) % modulo;
        }

        base = (base * base) % modulo;
        exposant /= 2;
    }

    resultat
}
/// Algorithme d'Euclide etendu : renvoie (pgcd, x, y)
/// tels que a*x + b*y = pgcd(a, b).
fn euclide_etendu(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (pgcd, x1, y1) = euclide_etendu(b, a % b);
        (pgcd, y1, x1 - (a / b) * y1)
    }
}

/// Calcule l'inverse de a modulo modulo.
fn inverse_modulaire(a: u64, modulo: u64) -> u64 {
    let (pgcd, x, _) = euclide_etendu(a as i64, modulo as i64);
    assert_eq!(pgcd, 1, "L'inverse modulaire n'existe pas");
    x.rem_euclid(modulo as i64) as u64
}

fn main() {
    let p = 61_u64;
    let q = 53_u64;
    let e = 17_u64;

    let n = p * q;
    let phi = (p - 1) * (q - 1);

    // d est l'inverse modulaire de e modulo phi(n).
    let d = inverse_modulaire(e, phi);

    let message = 65_u64;
    assert!(message < n, "Le message doit être inférieur à n");

    let chiffre = puissance_modulaire(message, e, n);
    let dechiffre = puissance_modulaire(chiffre, d, n);

    println!("Clé publique : ({e}, {n})");
    println!("Clé privée : ({d}, {n})");
    println!("Message initial : {message}");
    println!("Message chiffré : {chiffre}");
    println!("Message déchiffré : {dechiffre}");
}
