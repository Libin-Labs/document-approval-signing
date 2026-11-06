import packageExports = require('@lp-labs/document-approval-signing');
import type {
  ApprovalRequest,
  ApprovalSignature,
  ApprovalSigningOptions,
  ApprovalSigningTracker,
} from '@lp-labs/document-approval-signing';
const runtimeExports: unknown[] = [
  packageExports.createApprovalMessage,
  packageExports.signApproval,
  packageExports.createApprovalSigningTracker,
];
type PublicTypes =
  ApprovalRequest | ApprovalSignature | ApprovalSigningOptions | ApprovalSigningTracker;
void runtimeExports;
let publicType!: PublicTypes;
void publicType;
