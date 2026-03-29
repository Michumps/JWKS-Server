const {getDatabase, initDatabase} = require('./database');
const crypto = require('crypto');

const KEY_EXP = 2; // explicit key expiry, defined in hours

// Creates an RSA priv/pub key pair, to be used to sign JWTs
function genAndStoreKeys(genExpired = 1) {
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
	});

	const kid = Date.now(); // timestamp for kid
	const exp = Math.floor((Date.now() / 1000) + ((KEY_EXP * 3600) * genExpired)); // expiry set based on KEY_EXP and genExpired

	const db = getDatabase();

	// Inserts private key into database
	db.prepare('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)').run(kid, privateKey, exp);

	console.log(`Successfully generated key-pair with kid ${kid}`);

	return {kid, privateKey, publicKey, exp};
};

	function loadKeys() {
		const currentTime = Math.floor((Date.now() / 1000));

		const db = getDatabase();
		let keys = db.prepare('SELECT * FROM keys WHERE exp > ?').all(currentTime);

		return keys.map(row => ({
			kid: row.kid,
			privateKey: row.key,
			exp: row.exp
		}));
	}

	function loadExpKeys() {
		const currentTime = Math.floor((Date.now() / 1000));
		
		const db = getDatabase();
		let expKeys = db.prepare('SELECT * FROM keys WHERE exp < ?').all(currentTime);

		return expKeys.map(row => ({
			kid: row.kid,
			privateKey: row.key,
			exp: row.exp
		}));
	}

	function cleanExpiredKeys() {
		const currentTime = Math.floor(Date.now() / 1000); // convert to seconds
		
		const db = getDatabase();

		const info = db.prepare('DELETE FROM keys WHERE exp < ?').run(currentTime);

		console.log(`Successfully deleted ${info.changes} expired keys`);
	}

	// exports functions to be used in other files
	module.exports = {
		initDatabase,
		genAndStoreKeys,
		loadKeys,
		loadExpKeys,
		cleanExpiredKeys
	};