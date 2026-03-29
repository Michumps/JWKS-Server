const fs = require('fs').promises;
const path = require('path');
// functions to be implemented in test suite
const {
	genAndStoreKeys,
	loadKeys,
	loadExpKeys,
	cleanExpiredKeys
} = require('../keyGen');
const {initDatabase, closeDatabase, getDatabase} = require('../database');

// use a separate testing database
const TEST_DB_FILE = 'totally_not_my_testbase.db';

describe('Key Creation and Storage', () => {
	beforeAll(() => {
		// Close any previous database connection
		try {
			closeDatabase();
		} catch (e) {
			// No database to close
		}
		
		// Initialize database with test file
		initDatabase(TEST_DB_FILE);
		
		// Clear any existing data
		const db = getDatabase();
		try {
			db.exec('DELETE FROM keys');
		} catch (e) {
			// Ignore if table doesn't exist
		}
	});

	beforeEach(() => { // Clears database before each test
		const db = getDatabase();
		try {
			db.exec('DELETE FROM keys');
		} catch (e) {
			// Ignore error if table doesn't exist yet
		}
	});

	afterAll(() => {
		const db = getDatabase();
		try {
			db.exec('DELETE FROM keys');
		} catch (e) {
			// Ignore error
		}
		closeDatabase();
	})

	describe('initStorage', () => {
		test('Should initialize database without errors', () => {
			// Database already initialized in beforeAll
			const db = getDatabase();
			expect(db).toBeDefined();
		});

		test('Database should have keys table', () => {
			const db = getDatabase();
			const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").get();
			expect(result).toBeDefined();
			expect(result.name).toBe('keys');
		});
	});

	describe('genAndStoreKey', () => {
		test('Should have proper properties and types', () => {
			const result = genAndStoreKeys();

			// genAndStoreKeys returns proper values
			expect(result).toHaveProperty('kid');
			expect(result).toHaveProperty('privateKey');
			expect(result).toHaveProperty('publicKey');
			expect(result).toHaveProperty('exp');

			// ensures proper typing of properties
			expect(typeof result.kid).toBe('number');
			expect(result.privateKey).toContain('BEGIN RSA PRIVATE KEY');
			expect(result.publicKey).toContain('BEGIN PUBLIC KEY');
		});

		test('Ensure key is stored in database', () => {
			const result = genAndStoreKeys();

			// Query database to verify key was stored
			const db = getDatabase();
			const storedKey = db.prepare('SELECT * FROM keys WHERE kid = ?').get(result.kid);

			expect(storedKey).toBeDefined();
			expect(storedKey.kid).toBe(result.kid);
			expect(storedKey.key).toBe(result.privateKey);
			expect(storedKey.exp).toBe(result.exp);
		});

		test('Should set expiry some time in the future', () => {
			const result = genAndStoreKeys();

			const currentTime = Math.floor(Date.now() / 1000);
			const expectedExp = Math.floor(currentTime + (3600 * 2)) // Expected expiry should be two hours from now

			expect(result.exp).toBeGreaterThanOrEqual(expectedExp - 5); // Account for small time differences
			expect(result.exp).toBeLessThanOrEqual(expectedExp + 5);
		});

		test('Using expired parameter should set expiry in the past', () => {
			const result = genAndStoreKeys(-1);

			const currentTime = Math.floor(Date.now() / 1000);

			expect(result.exp).toBeLessThan(currentTime); // exp should be in the past
		});

		test('Should generate unique kid for each key', () => {
			const key1 = genAndStoreKeys();
			const key2 = genAndStoreKeys();

			expect(key1.kid).not.toBe(key2.kid);
		});

		test('Stored key should be retrievable from database', () => {
			const result = genAndStoreKeys();
			
			const db = getDatabase();
			const storedKey = db.prepare('SELECT * FROM keys WHERE kid = ?').get(result.kid);

			expect(storedKey).toBeDefined();
			expect(storedKey.key).toBe(result.privateKey);
		});
	});

	describe('loadKeys', () => {
		test('Should return empty array when no valid keys exist', () => {
			const validKeys = loadKeys();
			expect(validKeys).toEqual([]);
		});

		test('Should load valid keys that have not expired', () => {
			genAndStoreKeys();
			const validKeys = loadKeys();

			expect(validKeys).toHaveLength(1);
			expect(validKeys[0]).toHaveProperty('kid');
			expect(validKeys[0]).toHaveProperty('privateKey');
			expect(validKeys[0]).toHaveProperty('exp');
		});

		test('Should not load expired keys', () => {
			genAndStoreKeys(); // valid key
			genAndStoreKeys(-1); // expired key

			const validKeys = loadKeys();

			expect(validKeys).toHaveLength(1);
			expect(validKeys[0].exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});

		test('Should load multiple valid keys', () => {
			genAndStoreKeys();
			genAndStoreKeys();

			const validKeys = loadKeys();

			expect(validKeys.length).toBeGreaterThanOrEqual(2);
		});

		test('Loaded keys should contain valid PEM format private keys', () => {
			genAndStoreKeys();
			const validKeys = loadKeys();

			validKeys.forEach(key => {
				expect(key.privateKey).toContain('BEGIN RSA PRIVATE KEY');
				expect(key.privateKey).toContain('END RSA PRIVATE KEY');
			});
		});
	});

	describe('loadExpKeys', () => {
		test('Should return empty array when no expired keys exist', () => {
			genAndStoreKeys(); // valid key only
			const expiredKeys = loadExpKeys();

			expect(expiredKeys).toEqual([]);
		});

		test('Should load only expired keys', () => {
			genAndStoreKeys(); // valid key
			genAndStoreKeys(-1); // expired key

			const expiredKeys = loadExpKeys();

			expect(expiredKeys).toHaveLength(1);
			expect(expiredKeys[0].exp).toBeLessThan(Math.floor(Date.now() / 1000));
		});

		test('Should load multiple expired keys', () => {
			genAndStoreKeys(-1);
			genAndStoreKeys(-1);

			const expiredKeys = loadExpKeys();

			expect(expiredKeys.length).toBeGreaterThanOrEqual(2);
		});

		test('Expired keys should contain valid PEM format private keys', () => {
			genAndStoreKeys(-1);
			const expiredKeys = loadExpKeys();

			expiredKeys.forEach(key => {
				expect(key.privateKey).toContain('BEGIN RSA PRIVATE KEY');
				expect(key.privateKey).toContain('END RSA PRIVATE KEY');
			});
		});
	});

	describe('cleanExpiredKeys', () => {
		test('Should delete expired keys from database', () => {
			const expiredKey = genAndStoreKeys(-1);

			// Verify key exists before cleanup
			const db = getDatabase();
			let storedKeyBefore = db.prepare('SELECT * FROM keys WHERE kid = ?').get(expiredKey.kid);
			expect(storedKeyBefore).toBeDefined();

			// Clean expired keys
			cleanExpiredKeys();

			// Verify key no longer exists
			let storedKeyAfter = db.prepare('SELECT * FROM keys WHERE kid = ?').get(expiredKey.kid);
			expect(storedKeyAfter).toBeUndefined();
		});

		test('Should not delete valid keys', () => {
			const validKey = genAndStoreKeys();

			cleanExpiredKeys();

			const db = getDatabase();
			const storedKey = db.prepare('SELECT * FROM keys WHERE kid = ?').get(validKey.kid);
			expect(storedKey).toBeDefined();
		});

		test('Should delete only expired keys when both valid and expired exist', () => {
			const validKey = genAndStoreKeys();
			const expiredKey = genAndStoreKeys(-1);

			cleanExpiredKeys();

			const db = getDatabase();
			const validKeyStored = db.prepare('SELECT * FROM keys WHERE kid = ?').get(validKey.kid);
			const expiredKeyStored = db.prepare('SELECT * FROM keys WHERE kid = ?').get(expiredKey.kid);

			expect(validKeyStored).toBeDefined();
			expect(expiredKeyStored).toBeUndefined();
		});

		test('Should handle database with no keys gracefully', () => {
			// Database is empty from beforeEach
			expect(() => cleanExpiredKeys()).not.toThrow();
		});
	});
});

