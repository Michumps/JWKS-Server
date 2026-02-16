const fs = require('fs').promises;
const path = require('path');
// functions to be implemented in test suite
const {
	setKeyDir,
	initStorage,
	genAndStoreKeys,
	loadKeys,
	loadExpKeys,
	cleanExpiredKeys
} = require('../keyGen');

// use a separate testing directory
const TEST_KEY_DIR = path.join(__dirname, 'test_keys');

describe('Key Creation and Storage', () => {
	beforeAll(async () => {
		setKeyDir(TEST_KEY_DIR); // sets key directory for all tests to be test_keys
		await fs.mkdir(TEST_KEY_DIR, {recursive: true}); // creates test_keys directory
	});

	beforeEach(async () => { // Cleans test_keys before each test
		try {
			const testDir = await fs.readdir(TEST_KEY_DIR);

			for (const files of testDir) {
				// Skip .gitkeep to preserve directory structure
				if (files !== '.gitkeep') {
					await fs.unlink(path.join(TEST_KEY_DIR, files));
				}
			}
		} catch {
			// okay if directory doesn't exist
		}
	});

	afterAll(async () => {
		try {
			const testDir = await fs.readdir(TEST_KEY_DIR);

			for (const files of testDir) {
				// Skip .gitkeep to preserve directory structure
				if (files !== '.gitkeep') {
					await fs.unlink(path.join(TEST_KEY_DIR, files));
				}
			}
		} catch {
			// okay if directory doesn't exist
		}
	})

	describe('initStorage', () => {
		test('Should create KEY_DIR if it does not exist', async () => {
			// Remove the test directory first
			try {
				const testDir = await fs.readdir(TEST_KEY_DIR);
				for (const file of testDir) {
					await fs.unlink(path.join(TEST_KEY_DIR, file));
				}
				await fs.rmdir(TEST_KEY_DIR);
			} catch {
				// directory may not exist
			}

			// Call initStorage
			await initStorage();

			// Verify directory was created
			const dirExists = await fs.access(TEST_KEY_DIR).then(() => true).catch(() => false);
			expect(dirExists).toBe(true);
		});

		test('Should not throw error if KEY_DIR already exists', async () => {
			// Directory already created in beforeAll
			await expect(initStorage()).resolves.not.toThrow();
		});
	});

	describe('genAndStoreKey', () => {
		test('Should have proper properties and types', async () => {
			const result = await genAndStoreKeys();

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

		test('Ensure key and metadata files are created', async () => {
			const result = await genAndStoreKeys();

			// try and find resulting key and metadata files
			const keyPath = path.join(TEST_KEY_DIR, `key_${result.kid}.pem`);
			const metaPath = path.join(TEST_KEY_DIR, `key_${result.kid}.json`);

			// checks if files are valid and can be accessed
			const keyExists = await fs.access(keyPath).then(() => true).catch(() => false);
			const metaExists = await fs.access(metaPath).then(() => true).catch(() => false);

			expect(keyExists).toBe(true);
			expect(metaExists).toBe(true);
		})

		test('Should set expiry some time in the future', async () => {
			const result = await genAndStoreKeys();

			const currentTime = Math.floor(Date.now() / 1000);
			const expectedExp = Math.floor(currentTime + (3600 * 2)) // Expected expiry should be two hours from now (to change: expiry time set)

			expect(result.exp).toBeGreaterThanOrEqual(expectedExp - 5); // Account for small time differences
			expect(result.exp).toBeLessThanOrEqual(expectedExp + 5);
		});

		test('Using expired parameter should set expiry in the past', async () => {
			const result = await genAndStoreKeys(-1);

			const currentTime = Math.floor(Date.now() / 1000);

			expect(result.exp).toBeLessThan(currentTime); // exp should be in the past
		});

		test('Should generate unique kid for each key', async () => {
			const key1 = await genAndStoreKeys();
			const key2 = await genAndStoreKeys();

			expect(key1.kid).not.toBe(key2.kid);
		});

		test('Metadata file should contain correct properties', async () => {
			const result = await genAndStoreKeys();
			const metaPath = path.join(TEST_KEY_DIR, `key_${result.kid}.json`);
			const metaContent = await fs.readFile(metaPath, 'utf-8');
			const metadata = JSON.parse(metaContent);

			expect(metadata).toHaveProperty('kid');
			expect(metadata).toHaveProperty('exp');
			expect(metadata).toHaveProperty('created');
			expect(metadata.kid).toBe(result.kid);
			expect(metadata.exp).toBe(result.exp);
		});
	});

	describe('loadKeys', () => {
		test('Should return empty array when no valid keys exist', async () => {
			const validKeys = await loadKeys();
			expect(validKeys).toEqual([]);
		});

		test('Should load valid keys that have not expired', async () => {
			await genAndStoreKeys();
			const validKeys = await loadKeys();

			expect(validKeys).toHaveLength(1);
			expect(validKeys[0]).toHaveProperty('kid');
			expect(validKeys[0]).toHaveProperty('privateKey');
			expect(validKeys[0]).toHaveProperty('exp');
		});

		test('Should not load expired keys', async () => {
			await genAndStoreKeys(); // valid key
			await new Promise(resolve => setTimeout(resolve, 2)); // ensure different timestamp
			await genAndStoreKeys(-1); // expired key

			const validKeys = await loadKeys();

			expect(validKeys).toHaveLength(1);
			expect(validKeys[0].exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});

		test('Should load multiple valid keys', async () => {
			await genAndStoreKeys();
			await genAndStoreKeys();

			const validKeys = await loadKeys();

			expect(validKeys.length).toBeGreaterThanOrEqual(2);
		});

		test('Loaded keys should contain valid PEM format private keys', async () => {
			await genAndStoreKeys();
			const validKeys = await loadKeys();

			validKeys.forEach(key => {
				expect(key.privateKey).toContain('BEGIN RSA PRIVATE KEY');
				expect(key.privateKey).toContain('END RSA PRIVATE KEY');
			});
		});
	});

	describe('loadExpKeys', () => {
		test('Should return empty array when no expired keys exist', async () => {
			await genAndStoreKeys(); // valid key only
			const expiredKeys = await loadExpKeys();

			expect(expiredKeys).toEqual([]);
		});

		test('Should load only expired keys', async () => {
			await genAndStoreKeys(); // valid key
			await new Promise(resolve => setTimeout(resolve, 2)); // ensure different timestamp
			await genAndStoreKeys(-1); // expired key

			const expiredKeys = await loadExpKeys();

			expect(expiredKeys).toHaveLength(1);
			expect(expiredKeys[0].exp).toBeLessThan(Math.floor(Date.now() / 1000));
		});

		test('Should load multiple expired keys', async () => {
			await genAndStoreKeys(-1);
			await genAndStoreKeys(-1);

			const expiredKeys = await loadExpKeys();

			expect(expiredKeys.length).toBeGreaterThanOrEqual(2);
		});

		test('Expired keys should contain valid PEM format private keys', async () => {
			await genAndStoreKeys(-1);
			const expiredKeys = await loadExpKeys();

			expiredKeys.forEach(key => {
				expect(key.privateKey).toContain('BEGIN RSA PRIVATE KEY');
				expect(key.privateKey).toContain('END RSA PRIVATE KEY');
			});
		});
	});

	describe('cleanExpiredKeys', () => {
		test('Should delete expired key files', async () => {
			const expiredKey = await genAndStoreKeys(-1);
			const keyPath = path.join(TEST_KEY_DIR, `key_${expiredKey.kid}.pem`);
			const metaPath = path.join(TEST_KEY_DIR, `key_${expiredKey.kid}.json`);

			// Verify files exist before cleanup
			const keyExistsBefore = await fs.access(keyPath).then(() => true).catch(() => false);
			const metaExistsBefore = await fs.access(metaPath).then(() => true).catch(() => false);
			expect(keyExistsBefore).toBe(true);
			expect(metaExistsBefore).toBe(true);

			// Clean expired keys
			await cleanExpiredKeys();

			// Verify files no longer exist
			const keyExistsAfter = await fs.access(keyPath).then(() => true).catch(() => false);
			const metaExistsAfter = await fs.access(metaPath).then(() => true).catch(() => false);
			expect(keyExistsAfter).toBe(false);
			expect(metaExistsAfter).toBe(false);
		});

		test('Should not delete valid keys', async () => {
			const validKey = await genAndStoreKeys();
			const keyPath = path.join(TEST_KEY_DIR, `key_${validKey.kid}.pem`);
			const metaPath = path.join(TEST_KEY_DIR, `key_${validKey.kid}.json`);

			await cleanExpiredKeys();

			const keyExists = await fs.access(keyPath).then(() => true).catch(() => false);
			const metaExists = await fs.access(metaPath).then(() => true).catch(() => false);
			expect(keyExists).toBe(true);
			expect(metaExists).toBe(true);
		});

		test('Should delete only expired keys when both valid and expired exist', async () => {
			const validKey = await genAndStoreKeys();
			const expiredKey = await genAndStoreKeys(-1);

			await cleanExpiredKeys();

			const validKeyPath = path.join(TEST_KEY_DIR, `key_${validKey.kid}.pem`);
			const expiredKeyPath = path.join(TEST_KEY_DIR, `key_${expiredKey.kid}.pem`);

			const validKeyExists = await fs.access(validKeyPath).then(() => true).catch(() => false);
			const expiredKeyExists = await fs.access(expiredKeyPath).then(() => true).catch(() => false);

			expect(validKeyExists).toBe(true);
			expect(expiredKeyExists).toBe(false);
		});

		test('Should handle directory with no keys gracefully', async () => {
			// Directory is empty from beforeEach
			await expect(cleanExpiredKeys()).resolves.not.toThrow();
		});
	});
});
