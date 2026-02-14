const fs = require('fs').promises; // to be used for storing priv keys in file
const path = require('path');
const crypto = require('crypto');

const KEY_DIR = path.join(__dirname, 'private_keys'); // path to private_keys
const KEY_EXP = 2; // explicit key expiry (in hours)

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
async function genAndStoreKeys(genExpired = 1) {
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
	const exp = Math.floor((Date.now() / 1000) + ((KEY_EXP * 3600) * genExpired)); // expiry set based on KEY_EXP and genExpired

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

					}
				}
			}
		} catch (err) {
			console.error("Error loading keys: ", err);
		}

		return validKeys;
	}

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

	async function cleanExpiredKeys() {
		const currentTime = Date.now();
		let deletedKeys = 0;

		try {
			const keyDir = await fs.readdir(KEY_DIR); //  reads content of private_keys directory

			// checks metadata for each key and compares with current time to see if expired
			for (const files of keyDir) {
				if (files.endsWith('.json')) {
					const metaPath = path.join(KEY_DIR, files);
					const metaContent = await fs.readFile(metaPath, 'utf-8');
					const metadata = JSON.parse(metaContent);

					// if key is expired, delete key and metadata files from the private_keys directory
					if (metadata.exp < currentTime) {
						const keyPath = path.join(KEY_DIR, `key_${metadata.kid}.pem`);

						await fs.unlink(metaPath);
						await fs.unlink(keyPath);

						console.log(`Deleted expired key with kid: ${metadata.kid}`);
						deletedKeys ++;
					}
				}
			}

			if (deletedKeys > 0) console.log(`Successfully deleted ${deletedKeys} expired keys`);

		} catch (err) {
			console.error("Error loading keys: ", err);
		}
	}

	// exports functions to be used in other files
	module.exports = {
		initStorage,
		genAndStoreKeys,
		loadKeys,
		loadExpKeys,
		cleanExpiredKeys
	};