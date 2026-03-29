const fs = require('fs');
const path = require('path');
const {initDatabase, closeDatabase, getDatabase} = require('../database');

const TEST_DB_FILE = 'test_database.db';
const TEST_DB_PATH = path.join(__dirname, '..', 'data', TEST_DB_FILE);
const CUSTOM_TEST_DIR = 'test_custom_data';
const CUSTOM_DB_PATH = path.join(__dirname, '..', CUSTOM_TEST_DIR, 'custom_test.db');

describe('Database Module', () => {
	afterEach(() => {
		try {
			closeDatabase();
			// Clean up test database files
			if (fs.existsSync(TEST_DB_PATH)) {
				fs.unlinkSync(TEST_DB_PATH);
			}
			// Clean up custom directory
			if (fs.existsSync(CUSTOM_DB_PATH)) {
				fs.unlinkSync(CUSTOM_DB_PATH);
			}
			const customDir = path.join(__dirname, '..', CUSTOM_TEST_DIR);
			if (fs.existsSync(customDir)) {
				fs.rmdirSync(customDir);
			}
			// Clean up main data directory for test isolation
			const dataDir = path.join(__dirname, '..', 'data');
			if (fs.existsSync(dataDir)) {
				try {
					const files = fs.readdirSync(dataDir);
					for (const file of files) {
						fs.unlinkSync(path.join(dataDir, file));
					}
					fs.rmdirSync(dataDir);
				} catch (e) {
					// Ignore if directory still has files or can't be removed
				}
			}
		} catch (e) {
			// Ignore cleanup errors
		}
	});

	describe('initDatabase', () => {
		test('Should create database with custom file name', () => {
			const db = initDatabase(TEST_DB_FILE);
			
			expect(db).toBeDefined();
			expect(fs.existsSync(TEST_DB_PATH)).toBe(true);
		});

		test('Should create data directory if it does not exist', () => {
			// The data directory should be created by initDatabase
			const db = initDatabase(TEST_DB_FILE);
			
			const dataDir = path.join(__dirname, '..', 'data');
			expect(fs.existsSync(dataDir)).toBe(true);
			expect(db).toBeDefined();
		});

		test('Should handle case where directory already exists', () => {
			// First, ensure data directory exists
			const dataDir = path.join(__dirname, '..', 'data');
			if (!fs.existsSync(dataDir)) {
				fs.mkdirSync(dataDir, { recursive: true });
			}
			
			// Now initialize database - directory already exists
			const db = initDatabase(TEST_DB_FILE);
			expect(db).toBeDefined();
			expect(fs.existsSync(TEST_DB_PATH)).toBe(true);
		});

		test('Should create keys table on initialization', () => {
			const db = initDatabase(TEST_DB_FILE);
			
			// Query to check if table exists
			const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").get();
			expect(result).toBeDefined();
			expect(result.name).toBe('keys');
		});

		test('Should not throw error when creating database in existing directory', () => {
			// data directory should exist from previous tests
			expect(() => {
				initDatabase(TEST_DB_FILE);
			}).not.toThrow();
		});
	});

	describe('getDatabase', () => {
		test('Should return the initialized database', () => {
			initDatabase(TEST_DB_FILE);
			const db = getDatabase();
			
			expect(db).toBeDefined();
		});

		test('Should throw error if database not initialized', () => {
			closeDatabase();
			
			expect(() => getDatabase()).toThrow('Database not initialized');
		});
	});

	describe('closeDatabase', () => {
		test('Should close the database connection', () => {
			initDatabase(TEST_DB_FILE);
			closeDatabase();
			
			expect(() => getDatabase()).toThrow('Database not initialized');
		});

		test('Should handle closing non-existent database', () => {
			closeDatabase();
			
			expect(() => closeDatabase()).not.toThrow();
		});

		test('Should be idempotent', () => {
			initDatabase(TEST_DB_FILE);
			closeDatabase();
			closeDatabase();
			
			expect(() => getDatabase()).toThrow('Database not initialized');
		});
	});

	describe('Database functionality', () => {
		test('Should allow inserting and retrieving data', () => {
			const db = initDatabase(TEST_DB_FILE);
			
			const kid = Date.now();
			const exp = Math.floor(Date.now() / 1000) + 3600;
			const key = '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----';
			
			db.prepare('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)').run(kid, key, exp);
			const result = db.prepare('SELECT * FROM keys WHERE kid = ?').get(kid);
			
			expect(result).toBeDefined();
			expect(result.kid).toBe(kid);
			expect(result.key).toBe(key);
			expect(result.exp).toBe(exp);
		});

		test('Should support multiple operations in sequence', () => {
			const db = initDatabase(TEST_DB_FILE);
			
			const kid1 = Date.now();
			const kid2 = Date.now() + 1;
			
			db.prepare('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)').run(kid1, 'key1', 1000);
			db.prepare('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)').run(kid2, 'key2', 2000);
			
			const results = db.prepare('SELECT * FROM keys ORDER BY kid').all();
			expect(results).toHaveLength(2);
		});
	});
});
