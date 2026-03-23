const fs = require('fs') // used for directory creating and file permissions
const path = require('path');
const Database = require('better-sqlite3');

// module scope db for getDatabase to work
let db = null;

function initDatabase(dbFile = null) {
	
	// dbFile can be used instead; for testing
	const finalFile = dbFile || 'totally_not_my_private_keys.db'
	const finalPath = path.join(__dirname, 'data', finalFile);

	// Ensures that data/ is created if doesn't exist
	const dir = path.dirname(finalPath);
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	db = new Database(finalPath);

	db.exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY,
			key TEXT NOT NULL,
			exp INTEGER NOT NULL,
			created INTEGER NOT NULL
		)
		`);

	console.log("Database successfully created")

	return db;
}

function getDatabase() {
	if (!db) {
		throw new Error('Database not initialized');
	}

	return db;
}

module.exports = {
	initDatabase,
	getDatabase
};
