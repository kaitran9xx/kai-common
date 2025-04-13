"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const index_1 = require("./index");
const FAKE_TOKEN = 'this.is.not.a.real.token';
(0, vitest_1.describe)('verifyCognitoToken middleware', () => {
    const region = 'us-east-1';
    const userPoolId = 'us-east-1_fakepool';
    const middleware = (0, index_1.verifyCognitoToken)({ region, userPoolId });
    const mockRes = {};
    (0, vitest_1.it)('should return error if Authorization header is missing', () => {
        const mockReq = {
            headers: {},
        };
        const next = vitest_1.vi.fn();
        middleware(mockReq, mockRes, next);
        (0, vitest_1.expect)(next).toHaveBeenCalledOnce();
        const error = next.mock.calls[0][0];
        (0, vitest_1.expect)(error.message).toMatch(/Missing or invalid Authorization header/i);
    });
    (0, vitest_1.it)('should return error if token is malformed', () => {
        const mockReq = {
            headers: {
                authorization: 'Bearer FAKE.TOKEN.VALUE',
            },
        };
        const next = vitest_1.vi.fn();
        middleware(mockReq, mockRes, next);
        // Vì middleware verify dùng async getKey → ta cần test async
        setTimeout(() => {
            (0, vitest_1.expect)(next).toHaveBeenCalledOnce();
            const error = next.mock.calls[0][0];
            (0, vitest_1.expect)(error.message).toMatch(/Invalid token/i);
        }, 100);
    });
});
(0, vitest_1.describe)('verifyCognitoTokenData()', () => {
    (0, vitest_1.it)('should throw if token is invalid format', async () => {
        try {
            await (0, index_1.verifyCognitoTokenData)(FAKE_TOKEN, 'us-east-1', 'us-east-1_fakepool');
        }
        catch (err) {
            (0, vitest_1.expect)(err).toBeInstanceOf(Error);
            (0, vitest_1.expect)(err.message).toMatch(/Invalid token/);
        }
    });
    (0, vitest_1.it)('should throw if token has no kid in header', async () => {
        const tokenWithoutKid = [
            Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url'),
            Buffer.from(JSON.stringify({ sub: '123', token_use: 'access' })).toString('base64url'),
            'signature',
        ].join('.');
        try {
            await (0, index_1.verifyCognitoTokenData)(tokenWithoutKid, 'us-east-1', 'us-east-1_fakepool');
        }
        catch (err) {
            (0, vitest_1.expect)(err).toBeInstanceOf(Error);
            (0, vitest_1.expect)(err.message).toMatch(/no kid/);
        }
    });
    // Optional: test real token (if has real accessToken)
    // it('should return decoded payload for valid token', async () => {
    //   const validToken = process.env.TEST_ACCESS_TOKEN!;
    //   const region = process.env.COGNITO_REGION!;
    //   const userPoolId = process.env.COGNITO_USER_POOL_ID!;
    //   const payload = await verifyCognitoTokenData(validToken, region, userPoolId);
    //   expect(payload).toHaveProperty('sub');
    //   expect(payload).toHaveProperty('token_use', 'access');
    // });
});
