const jwt = require('jsonwebtoken');
const {loadKeys, loadExpKeys, genAndStoreKeys} = require('./keyGen');

async function signJWT(payload, expired = false) {
	let keys;
	let JWTexpiry;

	if (expired) {
		// check for expired keys, if there is none generate one
		await loadExpKeys().then(async expKeys => {
			if (expKeys.length === 0) await genAndStoreKeys(-1);
		});

		const expKeys = await loadExpKeys(); // should always have exp key

		keys = expKeys;
		JWTexpiry = '-1h'; // issue already expired JWT when using expired key
	} else {
		await loadKeys().then(async validKeys=> {
			if (validKeys.length === 0) genAndStoreKeys();
		}); // load valid keys

		let validKeys = await loadKeys();

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