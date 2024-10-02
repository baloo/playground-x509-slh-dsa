use std::{ops::Deref, str::FromStr, time::Duration};

use hex_literal::hex;
use pkcs8::EncodePrivateKey;
use slh_dsa::{Sha2_128s, SigningKey};
use x509_cert::{
    builder::{profile, Builder, CertificateBuilder},
    der::{pem::LineEnding, EncodePem},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    SubjectPublicKeyInfo,
};

fn main() {
    let signing_key = SigningKey::<Sha2_128s>::try_from(&hex!("A0FC7756572F3008F544399C25C9E087C28287AB54ADB1601FCACF85C2995A54404F690CD9A145512F61F2E4DE9292DA71371E754B3C2A79F2471E14608A2E34")[..]).unwrap();
    let pub_key = SubjectPublicKeyInfo::from_key(signing_key.as_ref()).unwrap();

    let serial_number = SerialNumber::generate(&mut rand::thread_rng()).unwrap();
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("Create root profile");

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate builder");

    let cert = builder.build(&signing_key).expect("Create certificate");

    println!(
        "{}",
        signing_key
            .to_pkcs8_pem(LineEnding::default())
            .unwrap()
            .deref()
    );

    println!("{}", cert.to_pem(LineEnding::default()).unwrap());
}
