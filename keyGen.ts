import Database from 'better-sqlite3';
import crypto from 'crypto';
import type { KeyRow } from './database.js';

/*
	Should work on cleaning up the way that Key expiry is handled.
	Shouldn't be hardcoded in a module level variable that is not
	able to be controlled from the server. TO_DO
*/ 

const KEY_EXP = 2; // explicit key expiry, defined in hours

// Creates an RSA priv/pub key pair, to be used to sign JWTs
function genAndStoreKeys(isExpired: 'valid' | 'expired' = 'valid', database: Database.Database) {
	const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		privateKeyEncoding: {
			type: 'pkcs1',
			format: 'pem'
		},
	});

	const genExpired = isExpired === 'valid' ? 1 : 0;

	const kid = Date.now(); // timestamp for kid
	const exp = Math.floor((Date.now() / 1000) + ((KEY_EXP * 3600) * genExpired)); // expiry set based on KEY_EXP and genExpired

	// Inserts private key into database
	database.prepare('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)').run(kid, privateKey, exp);

	console.log(`Successfully generated key-pair with kid ${kid}`);
};

function loadKeys(isExpired: 'valid' | 'expired' = 'valid', database: Database.Database):KeyRow[] {
	const currentTime = Math.floor((Date.now() / 1000));

	let keys:KeyRow[];

	if (isExpired === 'valid') {
		keys = database.prepare<[number], KeyRow>('SELECT * FROM keys WHERE exp > ?').all(currentTime);
	} else {
		keys = database.prepare<[number], KeyRow>('SELECT * FROM keys WHERE exp < ?').all(currentTime);
	}

	return keys;
}

function cleanExpiredKeys(database: Database.Database) {
	const currentTime = Math.floor(Date.now() / 1000); // convert to seconds

	const info = database.prepare('DELETE FROM keys WHERE exp < ?').run(currentTime);

	console.log(`Successfully deleted ${info.changes} expired keys`);
}

// exports functions to be used in other files
export {genAndStoreKeys, loadKeys, cleanExpiredKeys,}