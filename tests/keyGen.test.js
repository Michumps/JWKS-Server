const fs = require('fs').promises;
const path = require('path');
// functions to be implemented in test suite
const {
	setKeyDir,
	//initStorage,
	genAndStoreKeys,
	//loadKeys,
	//loadExpKeys,
	//cleanExpiredKeys
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
				await fs.unlink(path.join(TEST_KEY_DIR, files));
			}
		} catch {
			// okay if directory doesn't exist
		}
	});

	afterAll(async () => {
		try {
			const testDir = await fs.readdir(TEST_KEY_DIR);

			for (const files of testDir) {
				await fs.unlink(path.join(TEST_KEY_DIR, files));
			}

			await fs.rmdir(TEST_KEY_DIR);
		} catch {
			// okay if directory doesn't exist
		}
	})

	/*
	TO IMPLEMENT:
	initStorage tests
	loadKeys tests
	loadExpKeys tests
	cleanExpiredKeys tests
	*/


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
	});
/*
	describe('loadKeys', async () => {
		let validKeys = await loadKeys();

		expect(validKeys).toHaveLength(0); // no keys created yet, should be empty

		// generate valid key and reload valid keys
		await genAndStoreKeys();
		validKeys = loadKeys();

		expect(validKeys).toHaveLength(1); // should now have a valid key
	})
*/
});
