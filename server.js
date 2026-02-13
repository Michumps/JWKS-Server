const express = require('express');
const app = express();
const port = 8080;
const jwt = require('jsonwebtoken')
const {signJWT} = require('./JWTAuth');
const {genAndStoreKeys} = require('./keyGen');

app.use(express.json()); // middleware to allow JSON data

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

app.get('/.well-known/jwks.json', (req, res) => {

	res.send("GET TEST")

})

app.listen(port, () => {
	console.log(`Server started... listening on port: ${port}`)
});