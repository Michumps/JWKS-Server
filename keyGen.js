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
crypto.generateKeyPair('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: {
		type: 'spki',
		format: 'pem'
	},
	privateKeyEncoding: {
		type: 'pkcs1',
		format: 'pem'
	},
}, (err, publicKey, privateKey) => {
	console.log(`TESTING ONLY: ${publicKey}`);
});



