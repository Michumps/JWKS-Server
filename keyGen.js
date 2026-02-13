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

	async function loadKeys() {
		const currentTime = Math.floor((Date.now() / 1000));
		const validKeys = [];

		try {
			const keyDir = await fs.readdir(KEY_DIR); //  reads content of private_keys directory

			// checks metadata for each key and compares with current time to see if expired
			for (const files of keyDir) {
				if (files.endsWith('.json')) {
					const metaPath = path.join(KEY_DIR, files);
					const metaContent = await fs.readFile(metaPath, 'utf-8');
					const metadata = JSON.parse(metaContent);

					// if key is not expired, push to validKeys with kid and exp.
					if (metadata.exp > currentTime) {
						const keyPath = path.join(KEY_DIR, `key_${metadata.kid}.pem`);
						const privateKey = await fs.readFile(keyPath, 'utf-8');

						validKeys.push({
							kid: metadata.kid,
							privateKey,
							exp: metadata.exp
						});

					} else {
						console.log(`TEST; expired key with kid: ${metadata.kid} expired at ${metadata.exp}`);
					}
				}
			}
		} catch (err) {
			console.error("Error loading keys: ", err);
		}

		return validKeys;
	}

	loadKeys().then(validKeys => {
		console.log(validKeys)
	}); // TEMP OUTPUT TESTING
 

		async function loadExpKeys() {
		const currentTime = Math.floor((Date.now() / 1000));
		const expiredKeys = [];

		try {
			const keyDir = await fs.readdir(KEY_DIR); //  reads content of private_keys directory

			// checks metadata for each key and compares with current time to see if expired
			for (const files of keyDir) {
				if (files.endsWith('.json')) {
					const metaPath = path.join(KEY_DIR, files);
					const metaContent = await fs.readFile(metaPath, 'utf-8');
					const metadata = JSON.parse(metaContent);

					// if key is expired, push to expiredKeys with kid and exp.
					if (metadata.exp < currentTime) {
						const keyPath = path.join(KEY_DIR, `key_${metadata.kid}.pem`);
						const privateKey = await fs.readFile(keyPath, 'utf-8');

						expiredKeys.push({
							kid: metadata.kid,
							privateKey,
							exp: metadata.exp
						});

					}
				}
			}
		} catch (err) {
			console.error("Error loading keys: ", err);
		}

		return expiredKeys;
	}

	loadExpKeys().then(expiredKeys => {
		console.log(expiredKeys);
	}) // TEMP OUTPUT TESTING