export declare function getOtpSecret(size?: number): string;
export declare function getGoogleTotpUri(secret: string, user?: string, type?: string, sp?: string): string;
export declare function getOtpCode(secret: string, expire?: number): string;
export declare function checkCodeFromClient(secret: string, code: string | number): boolean;
