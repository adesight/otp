export declare function getOtpSecret(): string;
export declare function getGoogleTotpUri(secret: string, app: string, user: string, label?: string): string;
export declare function getOtpCode(secret: string, expire?: number): string;
export declare function checkCodeFromClient(secret: string, code: string | number): boolean;
