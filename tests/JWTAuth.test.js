const path = require('path');
const jwt = require('jsonwebtoken');
const {signJWT} = require('../JWTAuth');
const {setKeyDir, initStorage, genAndStoreKeys} = require('../keyGen');

const TEST_KEY_DIR = path.join(__dirname, 'test_keys');

describe('JWT Authorization', () => {
	beforeAll(async () => {
		setKeyDir(TEST_KEY_DIR); // ensures keys are added to test_keys
		initStorage();

		await genAndStoreKeys(); // Initial valid key for testing
		await genAndStoreKeys(-1); // Expired key for testing
	});

	describe('signJWT', () => {
		test('JWT should have proper structure', async () => {
			const payload = {user: "test"};
			const JWT = await signJWT(payload);

			expect(typeof JWT).toBe('string');

			// JWT should be split into 3 parts separated by dots
			const JWTparts = JWT.split('.');
			expect(JWTparts.length).toBe(3);
		});

        test('should include kid in JWT header', async () => {
            const payload = {user: "test"};
            const JWT = await signJWT(payload);
            
            const decoded = jwt.decode(JWT, { complete: true });
            
			// Ensure properties are present and valid
            expect(decoded.header).toHaveProperty('kid');
            expect(decoded.header.alg).toBe('RS256');
            expect(decoded.header.typ).toBe('JWT');
        });

        test('Should include correct payload claims', async () => {
            const payload = {user: "test"};
            const JWT = await signJWT(payload);
            
            const decoded = jwt.decode(JWT);
            
			// Ensure that payload has given payload values and standards
            expect(decoded.user).toBe('test');
            expect(decoded).toHaveProperty('iat');
            expect(decoded).toHaveProperty('exp');
        });

        test('Should create JWT that expires in the future for valid keys', async () => {
            const payload = {user: "test"};
            const JWT = await signJWT(payload);
            
            const decoded = jwt.decode(JWT);
            const currentTime = Math.floor(Date.now() / 1000);
            
            expect(decoded.exp).toBeGreaterThan(currentTime); // JWT expires in the future
        });

		test('Should sign JWT with expired key when expired parameter is true', async () => {
			const payload = {user: "test"}

			const JWT = await signJWT(payload, true);
			const decoded = jwt.decode(JWT);

			const currentTime = Math.floor(Date.now() / 1000);
			expect(decoded.exp).toBeLessThan(currentTime); // JWT expired before current time
		});
	});
});