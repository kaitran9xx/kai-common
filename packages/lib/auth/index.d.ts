import 'dotenv/config';
import type { Request, Response, NextFunction } from 'express';
export interface CognitoConfig {
    userPoolId: string;
    region: string;
}
export declare function verifyCognitoToken(config?: CognitoConfig): (req: Request, _res: Response, next: NextFunction) => void;
type DecodedAccessToken = {
    sub: string;
    username: string;
    email?: string;
    'cognito:groups'?: string[];
    [key: string]: any;
};
export declare function verifyCognitoTokenData(token: string, region: string, userPoolId: string): Promise<DecodedAccessToken>;
export {};
