const fs = require('fs').promises; // to be used for storing priv keys in file
const path = require('path');
const crypto = require('crypto');

const KEY_DIR = path.join(__dirname, 'private_keys'); // path to private_keys

// Ensures that private_keys is initialized, even if removed before program start
async function initStorage() {
	try {
		await fs.mkdir(KEY_DIR, {recursive: true});
		console.log('Key Storage successfully created');
	} catch (err) {
		console.error('Error creating Key Storage', err);
		throw err;
	}
}

// Creates an RSA priv/pub key pair, to be used to sign JWTs
async function genAndStoreKeys() {
	const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs1',
			format: 'pem'
		},
	}, (err, publicKey, privateKey) => {});

	const kid = Date.now(); // timestamp for kid
	const exp = Math.floor((Date.now() / 1000) + 3600); // expiry set to one hour (for now)

	console.log(`kid ${kid} and exp ${exp} successfully created`);

	const metadata = {
		kid,
		exp,
		created: Math.floor(Date.now() / 1000)
	};

	// creates .pem file for private key using restricted file permissions
	const keyPath = path.join(KEY_DIR, `key_${kid}.pem`);
	await fs.writeFile(keyPath, privateKey, {mode: 0o600});
	
	// creates .json file for priv key metadata
	const metadataPath = path.join(KEY_DIR, `key_${kid}.json`);
	await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2), {mode: 0o600});

	console.log(`Successfully generated key-pair with kid ${kid}`);

	return {kid, privateKey, publicKey, exp};
};

genAndStoreKeys();
