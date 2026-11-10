/** The audit-evidence API (0.11.0), exported from the main entry as `audit`. */

export {
  AUDIT_KINDS,
  BUNDLE_FORMAT_V1,
  BUNDLE_FORMAT_V2,
  BUNDLE_FORMAT_V3,
  MAX_PLANNED_RUNS,
  PAYLOAD_SCHEMAS,
  V3_REQUIRED,
  auditIdentity,
  parseAuditPayload,
  parseAuditPayloadIn,
  type AuditEventInput,
  type AuditKind,
  type AuditPayload,
  type BlobRef,
  type BundleFormat,
} from './schemas.js';
export { findingsDigest, finalFindingStatuses, freezeNonce, REPRODUCTION_FORMAT, REPRODUCTION_NAMESPACE, reproductionStatement, type ReproductionFields } from './profile.js';
export { allowedSignerLine, parseAllowedSigners, sshKeyFingerprint, sshSign, verifySshSignature, type AllowedSigner, type SshSignatureCheck } from './sshsig.js';
export { exportBundle, type BundleManifest } from './bundle.js';
export { verifyBundle } from './verify-bundle.js';
export { buildAuditPackage, DEFAULT_TSAS, renderPackage, stampAnchor, stampSums, type PackageResult, type StampResult } from './package.js';
export {
  ALLOWED_SIGNERS_FILE,
  AUDIT_PROFILE_CLAIMS,
  CLAIMS,
  LEGACY_CLAIMS,
  PENDING_SUFFIX,
  PROFILES,
  renderVerifyAudit,
  verifyAudit,
  VerifyAuditJsonSchema,
  VerifyAuditUsageError,
  type Claim,
  type Profile,
  type Verdict,
  type VerifyAuditOptions,
  type VerifyAuditResult,
} from './verify-audit.js';
