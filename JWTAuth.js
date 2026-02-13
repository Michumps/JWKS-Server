const jwt = require('jsonwebtoken');
const {loadKeys} = require('./keyGen');

async function signJWT(payload = {username: 'test'}) {
	let validKeys = await loadKeys(); // load valid keys

	// check if there are valid keys (always should be)
	if (validKeys.length === 0) {
		throw new Error('No valid keys available for signing');
	}

	privKey = validKeys[0]; // if there are keys select first one

	const options = {
		algorithm: 'RS256',
		keyid: privKey.kid.toString(),
		expiresIn: "1h",
	}

	// sign and return JWT
	const JWT = jwt.sign(payload, privKey, options);

	return JWT;
}