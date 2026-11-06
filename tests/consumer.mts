import {
  createApprovalMessage,
  signApproval,
  createApprovalSigningTracker,
} from '@lp-labs/document-approval-signing';
import type {
  ApprovalRequest,
  ApprovalSignature,
  ApprovalSigningOptions,
  ApprovalSigningTracker,
} from '@lp-labs/document-approval-signing';
const runtimeExports: unknown[] = [
  createApprovalMessage,
  signApproval,
  createApprovalSigningTracker,
];
type PublicTypes =
  ApprovalRequest | ApprovalSignature | ApprovalSigningOptions | ApprovalSigningTracker;
void runtimeExports;
let publicType!: PublicTypes;
void publicType;
