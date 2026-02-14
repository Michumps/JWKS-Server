const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {signJWT} = require('./JWTAuth');
const {genAndStoreKeys, loadKeys} = require('./keyGen');

const app = express();
const port = 8080;

app.use(express.json()); // middleware to allow JSON data

// POST Endpoint for signing JWTs
app.post('/auth', async (req, res) => {

	await genAndStoreKeys(); // temp for testing

	try {
		const expired = req.query.expired === 'true'; // checks if user wants expired key sign

		const payload = {
			user: 'test'
		};

		const JWT = await signJWT(payload, expired);

		res.json({JWT}); // respond with signed JWT
	} catch (err) {
		console.error('Failed to sign JWT', err);
	}

});

// GET Endpoint for JWKs
app.get('/.well-known/jwks.json', async (req, res) => {

	try {
		const keys = await loadKeys();

		// convert from private key to public to avoid having to store both
		const JWKS = keys.map(key => {
			const privKey = crypto.createPrivateKey(key.privateKey);
			const pubKeyPem = privKey.export({
				type: 'pkcs1',
				format: 'pem'
			});
			const pubKey = crypto.createPublicKey(pubKeyPem);
			const JWK = pubKey.export({format: 'jwk'});

			// return public keys in JWK format
			return {
				kid: key.kid.toString(),
				kty: JWK.kty,
				use: 'sig',
				alg: 'RS256',
				n: JWK.n,
				e: JWK.e
			};
		});

		res.json({keys: JWKS}); // return all keys in JWK format

	} catch (err) {
		// send error response if some failure happens
		console.error('Error generating JWKs: ', err);
		res.status(500).json({error: 'Error generating JWKs'});
	}

});

app.listen(port, () => {
	console.log(`Server started... listening on port: ${port}`)
});