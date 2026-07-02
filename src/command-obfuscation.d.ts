export type CommandObfuscationResult = {
    detected: boolean;
    matchedPatterns: string[];
};
export declare function detectCommandObfuscation(command: string | undefined): CommandObfuscationResult;
