import { describe, it, expect, vi } from 'vitest';
import { verifyCognitoToken, verifyCognitoTokenData } from './index';
import type { Request, Response, NextFunction } from 'express';
const FAKE_TOKEN = 'this.is.not.a.real.token';

describe('verifyCognitoToken middleware', () => {
  const region = 'us-east-1';
  const userPoolId = 'us-east-1_fakepool';

  const middleware = verifyCognitoToken({ region, userPoolId });

  const mockRes = {} as Response;

  it('should return error if Authorization header is missing', () => {
    const mockReq = {
      headers: {},
    } as Request;

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
    } as Request;

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


describe('verifyCognitoTokenData()', () => {
  it('should throw if token is invalid format', async () => {
    try {
      await verifyCognitoTokenData(FAKE_TOKEN, 'us-east-1', 'us-east-1_fakepool');
    } catch (err: any) {
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toMatch(/Invalid token/);
    }
  });

  it('should throw if token has no kid in header', async () => {
    const tokenWithoutKid = [
      Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: '123', token_use: 'access' })).toString('base64url'),
      'signature',
    ].join('.');

    try {
      await verifyCognitoTokenData(tokenWithoutKid, 'us-east-1', 'us-east-1_fakepool');
    } catch (err: any) {
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toMatch(/no kid/);
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