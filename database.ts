import fs from 'fs'; // used for directory creating and file permissions
import path from 'path'
import Database from 'better-sqlite3';

interface KeyRow {
	kid: number,
	key: string,
	exp: number
}

function initDatabase(dbFile: string | undefined):Database.Database {
	
	// dbFile can be used instead; for testing
	const finalFile = dbFile || 'totally_not_my_privateKeys.db'
	const finalPath = path.join(__dirname, 'data', finalFile);

	// Ensures that data/ is created if doesn't exist
	const dir = path.dirname(finalPath);
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	let db = new Database(finalPath);

	db.exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY,
			key TEXT NOT NULL,
			exp INTEGER NOT NULL
		)
		`);

	console.log("Database successfully created")

	return db;
}

export { initDatabase };
export type { KeyRow };