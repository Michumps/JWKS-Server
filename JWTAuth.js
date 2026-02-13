const jwt = require('jsonwebtoken');
const {loadKeys, loadExpKeys} = require('./keyGen');

async function signJWT(payload, expired = false) {
	let keys;
	let JWTexpiry;

	if (expired) {
		const expKeys = await loadExpKeys();

		// check if there are expired keys
		if (expKeys.length === 0) throw new Error("No expired keys available for signing");

		keys = expKeys;
		JWTexpiry = '-1h'; // issue already expired JWT when using expired key
	} else {
		const validKeys = await loadKeys(); // load valid keys

		// check if there are valid keys (always should be)
		if (validKeys.length === 0) throw new Error('No valid keys available for signing');

		keys = validKeys;
		JWTexpiry = '1h'; // JWT valid for 1 hour
	}

	privKey = keys[0].privateKey; // if there are keys select first one
	kid = keys[0].kid; // kid for priv key

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