const express = require('express');
const app = express();
const port = 8080;
const jwt = require('jsonwebtoken')

app.post('/auth', (req, res) => {

	req.body = {};

	res.send(req.body);

});

app.get('/.well-known/jwks.json', (req, res) => {

	res.send("GET TEST")

})

app.listen(port, () => {
	console.log(`Server started... listening on port: ${port}`)
});