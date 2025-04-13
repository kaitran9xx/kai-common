"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyCognitoToken = verifyCognitoToken;
exports.verifyCognitoTokenData = verifyCognitoTokenData;
require("dotenv/config");
// import jwt from 'jsonwebtoken';
const jwt = __importStar(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
function verifyCognitoToken(config) {
    const userPoolId = config?.userPoolId ?? process.env.COGNITO_USER_POOL_ID;
    const region = config?.region ?? process.env.COGNITO_REGION;
    if (!userPoolId || !region) {
        throw new Error('Cognito config missing. Please set region and userPoolId in .env or pass them directly.');
    }
    const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    const client = (0, jwks_rsa_1.default)({ jwksUri: `${issuer}/.well-known/jwks.json` });
    function getKey(header, callback) {
        client.getSigningKey(header.kid, (err, key) => {
            if (err)
                return callback(err);
            const signingKey = key.getPublicKey();
            callback(null, signingKey);
        });
    }
    return function (req, _res, next) {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return next(new Error('Missing or invalid Authorization header'));
        }
        const token = authHeader.split(' ')[1];
        jwt.verify(token, getKey, {
            issuer,
            algorithms: ['RS256'],
        }, (err, decoded) => {
            if (err)
                return next(new Error(`Invalid token: ${err.message}`));
            if (decoded.token_use !== 'access') {
                return next(new Error(`Expected access token, got ${decoded.token_use}`));
            }
            req.user = decoded;
            next();
        });
    };
}
async function verifyCognitoTokenData(token, region, userPoolId) {
    const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    const client = (0, jwks_rsa_1.default)({ jwksUri: `${issuer}/.well-known/jwks.json` });
    const getSigningKey = () => {
        return new Promise((resolve, reject) => {
            const decodedHeader = jwt.decode(token, { complete: true });
            if (!decodedHeader || !decodedHeader.header.kid) {
                return reject(new Error('Invalid token header (no kid)'));
            }
            client.getSigningKey(decodedHeader.header.kid, (err, key) => {
                if (err || !key)
                    return reject(err || new Error('Signing key not found'));
                resolve(key.getPublicKey());
            });
        });
    };
    const publicKey = await getSigningKey();
    return new Promise((resolve, reject) => {
        jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer }, (err, decoded) => {
            if (err)
                return reject(new Error(`Invalid token: ${err.message}`));
            const payload = decoded;
            if (payload.token_use !== 'access') {
                return reject(new Error(`Expected access token, got ${payload.token_use}`));
            }
            resolve(payload);
        });
    });
}
