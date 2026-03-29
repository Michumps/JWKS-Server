const express = require('express');
const crypto = require('crypto');
const {signJWT} = require('./JWTAuth');
const {genAndStoreKeys, loadKeys, cleanExpiredKeys} = require('./keyGen');
const {initDatabase, closeDatabase} = require('./database');

const app = express();
const port = 8080;

app.use(express.json()); // middleware to allow JSON data

// POST Endpoint for signing JWTs
app.post('/auth', async (req, res) => {

	try {
		const expired = req.query.expired === 'true'; // checks if user wants expired key sign

		const payload = {
			user: 'test'
		};

		const JWT = signJWT(payload, expired);

		res.status(201).json({JWT}); // respond with signed JWT
		
	} catch (err) {
		console.error('Failed to sign JWT', err);
		res.status(500).json({error: "Failed to sign JWT"})
	}

});

// GET Endpoint for JWKs
app.get('/.well-known/jwks.json', async (req, res) => {

	try {
		const keys = loadKeys();

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

		res.status(200).json({keys: JWKS}); // return all keys in JWK format

	} catch (err) {
		// send error response if some failure happens
		console.error('Error generating JWKs: ', err);
		res.status(500).json({error: 'Error generating JWKs'});
	}

});

// catch-all for unsupported methods and endpoints
app.all('/auth', (req, res) => {
	res.status(405).send('Unsupported Method');
})

app.all('/.well-known/jwks.json', (req, res) => {
	res.status(405).send('Unsupported Method');
});

app.use((req, res) => {
	res.status(404).send('Resource not found');
});

/* istanbul ignore next */ async function startServer(keyRotation = 1) {
	try {

		// Ensure data/ and database are initialized
		initDatabase();

		// Clean up expired keys since last program run
		cleanExpiredKeys();

		// Check if valid keys already exist, if not generate one
		const keys = loadKeys();

		if (keys.length === 0) {
			console.log('No valid keys, generating initial key');
			genAndStoreKeys();
			// Generate an expired key for testing
			genAndStoreKeys(0);
		}

		// Key rotation, time (in hours) defined by function input
		setInterval (() => {
			console.log('Rotating Keys');
			genAndStoreKeys();
			cleanExpiredKeys();
		}, keyRotation * (60 * 60 * 1000)); // default is 1 hour rotation

		// start server on port (8080)
		const server = app.listen(port, () => {
		console.log(`Server started... listening on port: ${port}`)

		});

		// Handle graceful shutdown to close database connection
		const gracefulShutdown = () => {
			console.log('Shutting down server...');
			server.close(() => {
				console.log('Server closed');
				closeDatabase();
				console.log('Database closed');
				process.exit(0);
			});
		};

		process.on('SIGINT', gracefulShutdown);
		process.on('SIGTERM', gracefulShutdown);

	} catch (err) { 
		// Exit entire process if server fails to start
		console.error('Error starting server: ', err);
		process.exit(1);
	}
}

/* istanbul ignore next */ if (require.main === module) startServer(); // only run if not required (for supertest)

module.exports = app;