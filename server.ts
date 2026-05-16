import express from 'express';
import crypto from 'crypto';
import { signJWT } from './JWTAuth.js';
import { genAndStoreKeys, loadKeys, cleanExpiredKeys } from './keyGen.js';
import { initDatabase } from './database.js';

const app = express();
const port = 8080;

app.use(express.json()); // middleware to allow JSON data

let db = initDatabase();

// POST Endpoint for signing JWTs
app.post('/auth', async (req, res) => {

	try {
		const expiredQuery = req.query.expired === 'true'; // checks if user wants expired key sign
		const isExpired = expiredQuery ? 'expired' : 'valid'

		let keys = loadKeys(isExpired, db);

		const payload = {
			user: 'test'
		};

		const JWT = signJWT(payload, isExpired, keys);

		res.status(201).json({JWT}); // respond with signed JWT
		
	} catch (err) {
		console.error('Failed to sign JWT', err);
		res.status(500).json({error: "Failed to sign JWT"})
	}

});

// GET Endpoint for JWKs
app.get('/.well-known/jwks.json', async (req, res) => {

	try {
		const keys = loadKeys('valid', db);

		// convert from private key to public to avoid having to store both
		const JWKS = keys.map(key => {
			const privKey = crypto.createPrivateKey(key.key);
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

		// Clean up expired keys since last program run
		cleanExpiredKeys(db);

		// Check if valid keys already exist, if not generate one
		const keys = loadKeys('expired', db);

		if (keys.length === 0) {
			console.log('No valid keys, generating initial key');
			genAndStoreKeys('valid', db);
			// Generate an expired key for testing
			genAndStoreKeys('expired', db);
		}

		const server = app.listen(port, () => {
		console.log(`Server started... listening on port: ${port}`)

		});

		// Handle graceful shutdown to close database connection
		const gracefulShutdown = () => {
			console.log('Shutting down server...');
			server.close(() => {
				console.log('Server closed');
				db.close();
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

/* istanbul ignore next */ if (import.meta.main) startServer(); // only run if not required (for supertest)

export { app };