export declare const MAX_SCAN_TEXT_CHARS = 10000;
export declare const MAX_CANDIDATES_PER_TEXT = 32;
export declare const MAX_CANDIDATE_CHARS = 2048;
export declare const MAX_DECODE_DEPTH = 2;
export declare const MAX_DECODE_OUTPUT_BYTES = 4096;
export type EncodedCandidateKind = "base64" | "base64url" | "base32" | "hex" | "url";
export type EncodedCandidateFinding = {
    kind: EncodedCandidateKind;
    tokenHash: string;
    decodedHash: string;
    decodedPreview: string;
    decodedLength: number;
    riskFlags: string[];
    confidence: "medium" | "high";
};
export type EncodedInspectionResult = {
    findings: EncodedCandidateFinding[];
    degraded: boolean;
    errorCount: number;
    scannedChars: number;
    candidateCount: number;
};
type InspectEncodedCandidateOptions = {
    analyzeDecoded?: (decoded: string, kind: EncodedCandidateKind) => string[];
    maxScanChars?: number;
    maxCandidates?: number;
};
type SanitizedEncodedSecretsResult = {
    value: string;
    changed: boolean;
    redactionCount: number;
};
export declare function inspectEncodedCandidates(text: string, options?: InspectEncodedCandidateOptions): EncodedInspectionResult;
export declare function buildObservedSecretVariants(secret: string): string[];
export declare function collectObservedSecretVariantMatches(text: string, observedSecrets: string[]): string[];
export declare function sanitizeEncodedSecretVariants(text: string, observedSecrets: string[], replacement: string): SanitizedEncodedSecretsResult;
export {};
