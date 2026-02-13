const jwt = require('jsonwebtoken');
const {loadKeys} = require('./keyGen');

async function signJWT(payload = {username: 'test'}) {
	let validKeys = await loadKeys(); // load valid keys

	// check if there are valid keys (always should be)
	if (validKeys.length === 0) {
		throw new Error('No valid keys available for signing');
	}

	privKey = validKeys[0].privateKey; // if there are keys select first one
	kid = validKeys[0].kid; // kid for priv key

	const options = {
		algorithm: 'RS256',
		keyid: kid.toString(),
		expiresIn: "1h",
	}

	// sign and return JWT
	const JWT = jwt.sign(payload, privKey, options);

	return JWT;
}

// export function
module.exports = {
	signJWT
};