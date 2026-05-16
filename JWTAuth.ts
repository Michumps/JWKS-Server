import jwt, { type SignOptions } from 'jsonwebtoken';
import type { KeyRow } from './database.js';

/*
	Could do with having a way to determine JWT expiry rather than having
	it hardcoded to being 1 hour. Not an issue for right now but something to
	consider improving in the future. TO_DO
*/

interface JWTPayloadJSON {
	user: string
}

function signJWT(payloadJSON:JWTPayloadJSON, expired: 'valid' | 'expired' = 'valid', keys:KeyRow[]) {

	if (keys.length === 0) {
		console.log("Error no keys available to sign JWT");
		return;
	}

	let firstKey = keys[0]!;

	const privKey = firstKey.key;
	const kid = String(firstKey.kid);

	let JWTexpiry = expired === 'valid' ? 3600 : -3600;

	const options: SignOptions = {
		algorithm: "RS256",
		keyid: kid,
		expiresIn: JWTexpiry,
	};

	// sign and return JWT
	const JWT = jwt.sign(payloadJSON, privKey, options);

	return JWT;
}

export { signJWT };