import { describe, it, expect, vi } from 'vitest';
import { verifyCognitoToken } from './index';
describe('verifyCognitoToken middleware', () => {
    const region = 'us-east-1';
    const userPoolId = 'us-east-1_fakepool';
    const middleware = verifyCognitoToken({ region, userPoolId });
    const mockRes = {};
    it('should return error if Authorization header is missing', () => {
        const mockReq = {
            headers: {},
        };
        const next = vi.fn();
        middleware(mockReq, mockRes, next);
        expect(next).toHaveBeenCalledOnce();
        const error = next.mock.calls[0][0];
        expect(error.message).toMatch(/Missing or invalid Authorization header/i);
    });
    it('should return error if token is malformed', () => {
        const mockReq = {
            headers: {
                authorization: 'Bearer FAKE.TOKEN.VALUE',
            },
        };
        const next = vi.fn();
        middleware(mockReq, mockRes, next);
        // Vì middleware verify dùng async getKey → ta cần test async
        setTimeout(() => {
            expect(next).toHaveBeenCalledOnce();
            const error = next.mock.calls[0][0];
            expect(error.message).toMatch(/Invalid token/i);
        }, 100);
    });
});
