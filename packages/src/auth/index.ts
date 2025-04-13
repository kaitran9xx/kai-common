import 'dotenv/config';
// import jwt from 'jsonwebtoken';
import * as jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import type { Request, Response, NextFunction } from 'express';

export interface CognitoConfig {
  userPoolId: string;
  region: string;
}

export function verifyCognitoToken(config?: CognitoConfig) {
  const userPoolId = config?.userPoolId ?? process.env.COGNITO_USER_POOL_ID;
  const region = config?.region ?? process.env.COGNITO_REGION;
  if (!userPoolId || !region) {
    throw new Error(
      'Cognito config missing. Please set region and userPoolId in .env or pass them directly.'
    );
  }
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const client = jwksRsa({ jwksUri: `${issuer}/.well-known/jwks.json` });

  function getKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) {
    client.getSigningKey(header.kid!, (err: any, key: any) => {
      if (err) return callback(err);
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    });
  }

  return function (req: Request, _res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return next(new Error('Missing or invalid Authorization header'));
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, getKey, {
      issuer,
      algorithms: ['RS256'],
    }, (err, decoded: any) => {
      if (err) return next(new Error(`Invalid token: ${err.message}`));
      if (decoded.token_use !== 'access') {
        return next(new Error(`Expected access token, got ${decoded.token_use}`));
      }

      (req as any).user = decoded;
      next();
    });
  };
}
