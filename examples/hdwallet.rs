use bip39::{Mnemonic, Language, Seed};
use hdwallet::{ExtendedPrivKey, DefaultKeyChain, Derivation, ExtendedPubKey};
use hdwallet::key_chain::KeyChain;
use ring::digest;
use base58::ToBase58;
use ripemd160::Ripemd160;
use ripemd160::Digest;
use secp256k1::{PublicKey, Secp256k1, SignOnly, VerifyOnly, SecretKey};
use bs58;
use bitcoincash_addr::{Address, Network, Scheme};
use bech32::{ToBase32, u5};
use ring::{hmac::{Key, HMAC_SHA512, Context}, signature};
use std::intrinsics::transmute;
use base32;
use crc16;
use ring::signature::KeyPair;
use sha2::Sha512Trunc256;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

fn main() {
	let phrase = "chat occur neutral super jar cruise then fragile track high check term";

	let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

	let seed = Seed::new(&mnemonic, "");

	println!("seed = {:?}", seed);

	btc_derivation(seed.clone());

	btc84_derivation(seed.clone());

	eth_derivation(seed.clone());

	xrp_derivation(seed.clone());

	bch_derivation(seed.clone());

	ltc_derivation(seed.clone());

	bnb_derivation(seed.clone());

	trx_derivation(seed.clone());

	atom_derivation(seed.clone());

	xlm_derivation(seed.clone());

	algo_derivation(seed.clone());

	yee_derivation(seed.clone());
}

fn btc_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BTC:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/0'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/0'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = btc_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "1Bi6zFVNtntP5MtDraNrAD7e469ifsQMwF");
}

fn btc84_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BTC84:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/84'/0'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/84'/0'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(&public_key.serialize()[..], "bc", Some(0));

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bc1qfvfvf72ydl745z2mnsd2p99n40tc3dlx6j5t3e");
}

fn eth_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("ETH:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/60'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/60'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = &format!("{}", private_key);
	let address = eth_address(public_key);

	println!("  address#0 private key = 0x{}", private_key);
	println!("  address#0 public key = 0x{}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "0x4c08adcf537d33b282c11f3f8f6a83e6cc48e0a0");
}

fn xrp_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("XRP:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/144'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/144'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = &format!("{}", private_key);
	let address = xrp_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "rDMNKAkDBdzpUqxctgBW5r7bpDLZTAdMF4");
}

fn bch_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BCH:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/145'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/145'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = bch_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bitcoincash:qraupdqydy3cnds2x647rnc3krqdjtt4y59azfs7e3");
}

fn ltc_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("LTC:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/84'/2'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/84'/2'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(&public_key.serialize()[..], "ltc", Some(0));

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "ltc1qn6wqy5kytcyt532q2t6wku8rnf0q6lr2pyyrtq");
}

fn bnb_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BNB:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/714'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/714'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(&public_key.serialize()[..], "bnb", None);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bnb1ktsp45pjwqm9n4qsdpzztaumvx5qla5crknwps");
}


fn trx_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("TRX:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/195'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/195'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = trx_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "TWZWdFSL6Kcn7hfAg6SHiGixUP5efEaBtW");
}


fn atom_derivation(seed: Seed) {
	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	let key_chain = DefaultKeyChain::new(master_key.clone());

	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("TRX:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/118'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/118'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(&public_key.serialize()[..], "cosmos", None);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "cosmos192strd0uann5jejvqqr38kevssa475da7dw277");
}

fn xlm_derivation(seed: Seed) {
	const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

	let seed = seed.as_bytes();

	let signature = {
		let signing_key = Key::new(HMAC_SHA512, b"ed25519 seed");
		let mut h = Context::with_key(&signing_key);
		h.update(seed);
		h.sign()
	};
	let sig_bytes = signature.as_ref();
	let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
//	println!("{:x?}", private_key);
//	println!("{:x?}", chain_code);

	let extended_private_key = ExtendedPrivKey { private_key: SecretKey::from_slice(private_key).expect("qed"), chain_code: chain_code.to_vec() };
	let derivation = Derivation {
		depth: 0u8,
		parent_key: None,
		key_index: None,
	};
	let key = serialize_extended_key::<XlmStrategy>(ExtendedKey::PrivKey(extended_private_key), &derivation);

	println!("XLM:");
	println!("  root key = {}", key);

	let path = vec![
		44u32 + HARDENED_KEY_START_INDEX,
		148u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
	];

	let mut temp_private_key = private_key.to_vec();
	let mut temp_chain_code = chain_code.to_vec();

	for index in path {
		let signature = {
			let signing_key = Key::new(HMAC_SHA512, &temp_chain_code);
			let mut h = Context::with_key(&signing_key);

			let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
			let mut data = vec![0x00];
			data.extend(&temp_private_key);
			data.extend(&index_buffer);

			h.update(&data);
			h.sign()
		};
		let sig_bytes = signature.as_ref();
		let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);

		temp_private_key = private_key.to_vec();
		temp_chain_code = chain_code.to_vec();

//		println!("{:?}", private_key);
//		println!("{:?}", chain_code);
	}

	let private_key = xlm_private_key(&temp_private_key);

	let key = signature::Ed25519KeyPair::from_seed_unchecked(&temp_private_key).expect("seed has valid length; qed");

	let public_key = xlm_public_key(key.public_key().as_ref());

	let address = public_key.clone();

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "GBHWWZDK5MBUQEMSCMWLXE4PSBXRBZKGP345GH4WPJZBLS7KCJ5RJHOW");
}

fn algo_derivation(seed: Seed) {
	const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

	let seed = seed.as_bytes();

	let signature = {
		let signing_key = Key::new(HMAC_SHA512, b"ed25519 seed");
		let mut h = Context::with_key(&signing_key);
		h.update(seed);
		h.sign()
	};
	let sig_bytes = signature.as_ref();
	let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
//	println!("{:x?}", private_key);
//	println!("{:x?}", chain_code);

	let extended_private_key = ExtendedPrivKey { private_key: SecretKey::from_slice(private_key).expect("qed"), chain_code: chain_code.to_vec() };
	let derivation = Derivation {
		depth: 0u8,
		parent_key: None,
		key_index: None,
	};
	let key = serialize_extended_key::<XlmStrategy>(ExtendedKey::PrivKey(extended_private_key), &derivation);

	println!("ALGO:");
	println!("  root key = {}", key);

	let path = vec![
		44u32 + HARDENED_KEY_START_INDEX,
		283u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
	];

	let mut temp_private_key = private_key.to_vec();
	let mut temp_chain_code = chain_code.to_vec();

	for index in path {
		let signature = {
			let signing_key = Key::new(HMAC_SHA512, &temp_chain_code);
			let mut h = Context::with_key(&signing_key);

			let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
			let mut data = vec![0x00];
			data.extend(&temp_private_key);
			data.extend(&index_buffer);

			h.update(&data);
			h.sign()
		};
		let sig_bytes = signature.as_ref();
		let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);

		temp_private_key = private_key.to_vec();
		temp_chain_code = chain_code.to_vec();

//		println!("{:?}", private_key);
//		println!("{:?}", chain_code);
	}

	let key = signature::Ed25519KeyPair::from_seed_unchecked(&temp_private_key).expect("seed has valid length; qed");

	let private_key = algo_key(&temp_private_key);

	let public_key = algo_key(key.public_key().as_ref());

	let address = public_key.clone();

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "RSY4ZSL3OHVIRAAF3F7MEZCGSDONN6TZ3AGJ5GGYIAB4PRUCN2BULX3UMQ");

}

fn yee_derivation(seed: Seed) {
	const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

	let seed = seed.as_bytes();

	let signature = {
		let signing_key = Key::new(HMAC_SHA512, b"ed25519 seed");
		let mut h = Context::with_key(&signing_key);
		h.update(seed);
		h.sign()
	};
	let sig_bytes = signature.as_ref();
	let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
//	println!("{:x?}", private_key);
//	println!("{:x?}", chain_code);

	let extended_private_key = ExtendedPrivKey { private_key: SecretKey::from_slice(private_key).expect("qed"), chain_code: chain_code.to_vec() };
	let derivation = Derivation {
		depth: 0u8,
		parent_key: None,
		key_index: None,
	};
	let key = serialize_extended_key::<XlmStrategy>(ExtendedKey::PrivKey(extended_private_key), &derivation);

	println!("YEE:");
	println!("  root key = {}", key);

	let path = vec![
		44u32 + HARDENED_KEY_START_INDEX,
		4096u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
		0u32 + HARDENED_KEY_START_INDEX,
	];

	let mut temp_private_key = private_key.to_vec();
	let mut temp_chain_code = chain_code.to_vec();

	for index in path {
		let signature = {
			let signing_key = Key::new(HMAC_SHA512, &temp_chain_code);
			let mut h = Context::with_key(&signing_key);

			let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
			let mut data = vec![0x00];
			data.extend(&temp_private_key);
			data.extend(&index_buffer);

			h.update(&data);
			h.sign()
		};
		let sig_bytes = signature.as_ref();
		let (private_key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);

		temp_private_key = private_key.to_vec();
		temp_chain_code = chain_code.to_vec();

//		println!("{:?}", private_key);
//		println!("{:?}", chain_code);
	}

	let key = signature::Ed25519KeyPair::from_seed_unchecked(&temp_private_key).expect("seed has valid length; qed");

	let public_key = key.public_key().as_ref();

	let private_key = to_hex(&temp_private_key);

	let public_key_hex = to_hex(public_key);

	let address = bech32_address(public_key, "yee", None);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key_hex);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "yee1wnagctf0q30v665z3cfcjlukp3ucg7zdmuckwt");

}

enum ExtendedKey {
	PrivKey(ExtendedPrivKey),
	PubKey(ExtendedPubKey),
}

trait Strategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>);
}

struct BtcStrategy;

impl Strategy for BtcStrategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>) {
		(from_hex("0x0488ADE4"), from_hex("0x0488B21E"))
	}
}

struct Btc84Strategy;

impl Strategy for Btc84Strategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>) {
		(from_hex("0x04b2430c"), from_hex("0x04b24746"))
	}
}

struct XlmStrategy;

impl Strategy for XlmStrategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>) {
		(from_hex("0x00000000"), from_hex("0x00000000"))
	}
}

fn serialize_extended_key<S: Strategy>(extended_key: ExtendedKey, derivation: &Derivation) -> String {
	let version_bytes = S::version_bytes();
	let version_bytes = match extended_key {
		ExtendedKey::PrivKey(_) => version_bytes.0,
		ExtendedKey::PubKey(_) => version_bytes.1,
	};

	let parent_fingerprint = match derivation.parent_key {
		Some(ref key) => {
			let pubkey = ExtendedPubKey::from_private_key(key);
			let buf = digest::digest(&digest::SHA256, &pubkey.public_key.serialize());
			let mut hasher = Ripemd160::new();
			hasher.input(&buf.as_ref());
			hasher.result()[0..4].to_vec()
		}
		None => vec![0; 4],
	};

	let mut buf: Vec<u8> = Vec::with_capacity(112);
	buf.extend_from_slice(&version_bytes);
	buf.extend_from_slice(&derivation.depth.to_be_bytes());
	buf.extend_from_slice(&parent_fingerprint);
	match derivation.key_index {
		Some(key_index) => {
			buf.extend_from_slice(&key_index.raw_index().to_be_bytes());
		}
		None => buf.extend_from_slice(&[0; 4]),
	}
	match extended_key {
		ExtendedKey::PrivKey(ref key) => {
			buf.extend_from_slice(&key.chain_code);
			buf.extend_from_slice(&[0]);
			buf.extend_from_slice(&key.private_key[..]);
		}
		ExtendedKey::PubKey(ref key) => {
			buf.extend_from_slice(&key.chain_code);
			buf.extend_from_slice(&key.public_key.serialize());
		}
	}
	assert_eq!(buf.len(), 78);

	let check_sum = {
		let buf = digest::digest(&digest::SHA256, &buf);
		digest::digest(&digest::SHA256, &buf.as_ref())
	};

	buf.extend_from_slice(&check_sum.as_ref()[0..4]);
	(&buf).to_base58()
}

fn from_hex(hex_string: &str) -> Vec<u8> {
	if hex_string.starts_with("0x") {
		hex::decode(&hex_string[2..]).expect("decode")
	} else {
		hex::decode(hex_string).expect("decode")
	}
}

fn to_hex(buf: &[u8]) -> String {
	hex::encode(buf)
}

fn btc_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	bs58::encode(&a).with_check().into_string()
}

fn btc_wif(private_key: &[u8]) -> String {
	let mut a = Vec::new();
	a.push(0x80);
	a.extend(private_key);
	a.push(0x01);
	bs58::encode(a).with_check().into_string()
}

fn ltc_wif(private_key: &[u8]) -> String {
	let mut a = Vec::new();
	a.push(0xB0);
	a.extend(private_key);
	a.push(0x01);
	bs58::encode(a).with_check().into_string()
}

fn eth_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize_uncompressed();

	let public_key = &public_key[1..];

	let mut hasher = sha3::Keccak256::default();
	hasher.input(public_key);

	let out = hasher.result();

	let out = to_hex(&out.as_slice()[12..32]);

	format!("0x{}", out)
}

fn xrp_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	bs58::encode(&a).with_alphabet(bs58::alphabet::RIPPLE).with_check().into_string()
}

fn bch_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	let address = bs58::encode(&a).with_check().into_string();

	let mut address = Address::decode(&address).unwrap();
	address.network = Network::Main;
	address.scheme = Scheme::CashAddr;

	address.encode().unwrap()
}

// https://bitcointalk.org/index.php?topic=4992632.0
// some coin does not have a segwit version, like BNB: https://docs.binance.org/blockchain.html#address
fn bech32_address(public_key: &[u8], hrp: &str, segwit_version: Option<u8>) -> String {
	let buf = digest::digest(&digest::SHA256, public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let mut buf = hasher.result().to_vec().to_base32();
	if let Some(segwit_version) = segwit_version {
		buf.insert(0, u5::try_from_u8(segwit_version).unwrap());
	}
	let b = bech32::encode(
		hrp,
		buf,
	).unwrap();
	let encoded = b.to_string();
	encoded
}

fn trx_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize_uncompressed();

	let public_key = &public_key[1..];

	let mut hasher = sha3::Keccak256::default();
	hasher.input(public_key);

	let out = hasher.result();

	let out = &out.as_slice()[12..32];

	let mut a = Vec::new();
	a.push(0x41);
	a.extend(out);
	bs58::encode(&a).with_check().into_string()
}

fn xlm_public_key(public_key: &[u8]) -> String {
	const SEED: u8 = 6u8 << 3;

	let mut data = Vec::new();
	data.push(SEED);
	data.extend(public_key);

	let checksum = crc16::State::<crc16::XMODEM>::calculate(&data);

	let checksum: [u8; 2] = unsafe { transmute(checksum.to_le()) }; // or .to_le()

	data.extend(&checksum);

	base32::encode(base32::Alphabet::RFC4648 { padding: true }, &data)
}


fn xlm_private_key(private_key: &[u8]) -> String {
	const SEED: u8 = 18u8 << 3;

	let mut data = Vec::new();
	data.push(SEED);
	data.extend(private_key);

	let checksum = crc16::State::<crc16::XMODEM>::calculate(&data);

	let checksum: [u8; 2] = unsafe { transmute(checksum.to_le()) }; // or .to_le()

	data.extend(&checksum);

	base32::encode(base32::Alphabet::RFC4648 { padding: true }, &data)
}


fn algo_key(key: &[u8]) -> String {

	let mut hasher = Sha512Trunc256::new();
	hasher.input(key);
	let result = hasher.result();

	let mut data = Vec::new();
	data.extend(key);
	data.extend(&result[28..32]);

	base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data)

}