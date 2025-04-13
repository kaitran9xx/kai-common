import 'dotenv/config';
import type { Request, Response, NextFunction } from 'express';
export interface CognitoConfig {
    userPoolId: string;
    region: string;
}
export declare function verifyCognitoToken(config?: CognitoConfig): (req: Request, _res: Response, next: NextFunction) => void;
