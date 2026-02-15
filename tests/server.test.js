const request = require('supertest');

// mock keyGen so no files are created during testing
jest.mock('../keyGen');

const {initStorage, genAndStoreKeys, loadKeys} = require('../keyGen');

// mock values so no key gen or files are created
loadKeys.mockResolvedValue([
	{
		kid: 1234567890,
		privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAjm02A5EyYgG2uyznlnogs8IieMjt6vNXBzs9Dg2m4OV2Eny7
+RWPJVTnmnFcLYmzWb+RvJPp9MQT6PNn9FKodrkQEyCvrkLy51QoFHXEEPZW9MR7
vyJKgW5LWqdPxcfC+YSNcl/GDg1n2c3g3bzcpX7p1PqBcX/KYOimWqpNOFoBtMBj
m/9RA+sa2nccuhdl0BG/RQBzvBMWQIebeJdpR0bvuiw8kboQXfBpS45MH7PtzsPc
hBOCZo5/XRdhxCkJLY5LTGxH5ukXttwW5TJe6Kw5BKvFhDmSmljvGiDNEjKfNW3k
kVF9FxniSYvJqpYaGXx73CKcBjk4uvEk00XLwwIDAQABAoIBAQCNMBgWay4916MU
Y8xj8EdQy0cu40hu27FPGttIfiIK2Y01gG862bNgd41sHaoZ/mJLuss23I5VNLbj
+772haY4ovYbcBCXuAhhZ5yfw6qMghbrZ4egjta6/eI3SJqc3o0amts5IVYNgh6L
3DpotZspd+lHVtlQ8TRm4tpeEGqiS6LzjoTCfClTUq75qJdqjcT8bOcztYtW/Svv
cNPEXjJd1Ksfaw8Gj6OQ2n87+iZcQO43U/SSnsRUA3fg4W8uv/9/HhYnyjEqO1l5
x9CGTNQe5kUeeJNiiJ7jDmUpYPofjeCK6V26KdKTC/YLXDaP4nk9gMzsQsE3c1lP
L1RaEtR5AoGBANKjfkzxX6usCI28jrAK0rWMAEXAT6s8wZFmd/omWvjsfo/Prjg1
AXfZOG2KAIXUJn8MUTvuQw/plRBPhzK6TmMkdOn2xRtkzVWzJLaRYL5Aeqf3UQO1
oH1VZBO2Z9R8I/8rObqs3WrDr3O5RzGjoK1+gXQxeR2+/soH3E8ZhT3dAoGBAK0Z
MD6wk/WOsFo+fkiyId5VQ87DjMBctBH5HOKTE5fVgRuPeYj0z/pcsviG5wdWt/XQ
XmW4ZvwiIbm3KdV8oJGyx/ENNc+WJsrVL6piTnm68dprr7rQ805iOaEHO0Gp89hr
uwYAJhQ8y558dlCeJGruSCOgv8hXpFlbG6lcvqYfAoGBALyh0X+SQTz56QcVLysT
5jLS14Offzk4RZiyjQslwh5dm9GqCLkpLtFnZBMknOc8X+Uy4KSs8L2VTvq2Xbre
AUjj4xeK+GVZ1lDDB0O/2UVHdRBqeNC7nKfhCqhkl4NAUPQ4f5BfMkJkUAFwkQMx
J7l3KvMlQvOSkZXXiEIF9r65AoGAChY8rHqHtLiC6E9Z9oyC0rzvPZ5BlngQejel
CkL90kw7wMpkj6mMcQ9z0m2yCshv4eApkA3l2m12v6a/xlQD21mqsw5NA3LBgfJY
W7pszkUpkMvTqrRAaWHp78tHFbV8ozDr7haWIXnFd8/S6TG994k5JPJaGqeYySg4
/W6NIYsCgYAYYaSMuZhg6EHxB3eVerTbm2Pfr8vP5BuOitKqP0tA2z2enRg/LKTd
czLKpmA09UDO9RLTFXzf/MaJt77EO2fi/6ummwHvcsI3lMS8iuwqurbB/paGS745
lDhMl8UskKHJvLVTdNhWsyQAp8fPt0sVW6cTMI4+EB1r/vpSxCigfg==
-----END RSA PRIVATE KEY-----`,
		exp: Math.floor((Date.now() / 1000) + 7200) // expires 2 hours from now
	}
]);

initStorage.mockResolvedValue();
genAndStoreKeys.mockResolvedValue({
	kid: 1234567890,
	privateKey: 'test-priv-key',
	publicKey: 'test-pub-key',
	exp: Math.floor((Date.now() / 1000) + 7200)
});

let app;

describe('JWKS Server', () => {
	beforeAll(() => {
		app = require('../server');
	});

	describe ('POST /auth', () => {
		test('201 status with JWT token', async () => {
			// expected POST to /auth
			const response = await request(app)
				.post('/auth')
				.expect(201)
				.expect('Content-Type', /json/);

				expect(response.body).toHaveProperty('JWT');
				expect(typeof response.body.JWT).toBe('string');
		});

		test('JWT should have three parts', async () => {
			const response = await request(app)
				.post('/auth')
				.expect(201)
				.expect('Content-Type', /json/);

			const JWTparts = response.body.JWT.split('.');
			expect(JWTparts).toHaveLength(3)
		});

		// handle all invalid HTTP methods
		test('Should respond 404 to invalid GET method', async () => {
			await request(app)
				.get('/auth')
				.expect(405);
		});

		test('Should respond 404 to invalid PUT method', async () => {
			await request(app)
				.put('/auth')
				.expect(405);
		});

		test('Should respond 404 to invalid DELETE method', async () => {
			await request(app)
				.delete('/auth')
				.expect(405);
		});
	});

	describe('GET /.well-known/jwks.json', () => {
        test('should return 200 with JWKS', async () => {
			// expected GET request
            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200)
                .expect('Content-Type', /json/);

            expect(response.body).toHaveProperty('keys');
            expect(Array.isArray(response.body.keys)).toBe(true);
        });

        test('should return keys with correct JWK format', async () => {
            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200);

            const keys = response.body.keys;
            expect(keys.length).toBeGreaterThan(0);

			// check each key has correct properties
            keys.forEach(key => {
                expect(key).toHaveProperty('kid');
                expect(key).toHaveProperty('kty');
                expect(key).toHaveProperty('use');
                expect(key).toHaveProperty('alg');
                expect(key).toHaveProperty('n');
                expect(key).toHaveProperty('e');
                
                expect(key.kty).toBe('RSA');
                expect(key.use).toBe('sig');
                expect(key.alg).toBe('RS256');
        	});
        });

		// handle all invalid HTTP methods
		test('Should respond 404 to invalid POST method', async () => {
			await request(app)
				.post('/.well-known/jwks.json')
				.expect(405);
		});

		test('Should respond 404 to invalid PUT method', async () => {
			await request(app)
				.put('/.well-known/jwks.json')
				.expect(405);
		});

		test('Should respond 404 to invalid DELETE method', async () => {
			await request(app)
				.delete('/.well-known/jwks.json')
				.expect(405);
		});
	});
});
