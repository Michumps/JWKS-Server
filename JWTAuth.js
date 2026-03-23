const jwt = require('jsonwebtoken');
const {loadKeys, loadExpKeys, genAndStoreKeys} = require('./keyGen');

function signJWT(payload, expired = false) {
	let keys;
	let JWTexpiry;

	// Could clean up logic and use ternary operator with functions for exp or valid; IMPROVE
	if (expired) {
		// check for expired keys, if there is none generate one
		let expKeys = loadExpKeys();

		if(expKeys.length === 0) {
			const expKey = genAndStoreKeys(-1);
			expKeys = [expKey];
		}

		// final check to see if there are expired keys (always should be)
		if (expKeys.length === 0) throw new Error('No expired keys available for signing');

		keys = expKeys;
		JWTexpiry = '-1h'; // issue already expired JWT when using expired key
	} else {

		// check for valid keys, if there are none generate one
		let validKeys = loadKeys();

		if (validKeys.length === 0) {
			const validKey = genAndStoreKeys();
			validKeys = [validKey];
		}

		// check if there are valid keys (always should be)
		if (validKeys.length === 0) throw new Error('No valid keys available for signing');

		keys = validKeys;
		JWTexpiry = '1h'; // JWT valid for 1 hour
	}

	const privKey = keys[0].privateKey; // if there are keys select first one
	const kid = keys[0].kid; // kid for priv key

	const options = {
		algorithm: 'RS256',
		keyid: kid.toString(),
		expiresIn: JWTexpiry,
	}

	// sign and return JWT
	const JWT = jwt.sign(payload, privKey, options);

	return JWT;
}

// export function
module.exports = {
	signJWT
};