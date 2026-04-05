use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() {
    let key = SigningKey::generate(&mut OsRng);
    let kp = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
    let did = kp.did();
    let mut ad = pap_marketplace::AgentAdvertisement::new(
        "Travel Search Agent",
        "TravelCorp",
        &did,
        vec!["schema:SearchAction".into()],
        vec!["schema:Flight".into()],
        vec!["schema:Person.name".into()],
        vec!["schema:Flight".into()],
    );
    ad.sign(&key).expect("Ed25519 is always supported");
    println!("{}", ad.to_json());
}
