# @lp-labs/document-approval-signing

Bind a detached approval signature to a request ID, approver, document revision, SHA-256 digest, and
expiry. Track explicitly verified approvals with a threshold and stale-revision rejection.

## Install

```bash
npm install @lp-labs/document-approval-signing
```

No runtime or peer dependencies. ESM, CommonJS, and declarations are provided.

## Quickstart

```js
import { webcrypto } from 'node:crypto';
import { createApprovalSigningTracker, signApproval } from '@lp-labs/document-approval-signing';

const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
  'sign',
  'verify',
]);
const request = {
  id: 'release-42',
  revision: 1,
  digest: new Uint8Array(32).fill(7),
  expiresAt: Date.now() + 60_000,
};
const signature = await signApproval(request, 'alice', keys.privateKey, {
  name: 'ECDSA',
  namedCurve: 'P-256',
});
const tracker = createApprovalSigningTracker({
  ...request,
  approvers: ['alice'],
  verify: (_id, message, value) =>
    webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keys.publicKey, value, message),
});
await tracker.approve(signature);
if (tracker.status !== 'approved') throw new Error('Approval not complete');
```

## API and customization

`createApprovalMessage(request, approver)` returns stable length-prefixed UTF-8/byte message data.
`signApproval(request, approver, privateKey, algorithm, subtle?)` produces a detached ECDSA P-256 or
RSA-PSS/SHA-256 signature bound to that message. `createApprovalSigningTracker(options)` validates
the approver allowlist and quorum and returns `approve(signature, now?)`, `snapshot()`, and a live
`status`. `ApprovalRequest`, `ApprovalSignature`, `ApprovalSigningOptions`, and
`ApprovalSigningTracker` are TypeScript types.

Document digests must be exactly 32 bytes. Request/approver IDs are 1–256 characters; revision and
expiry are nonnegative safe integers; at most 10,000 unique approvers are permitted. Threshold
defaults to all approvers. Approval callbacks must perform actual signature verification for the
named approver. Revisions/digests are compared before verification; duplicate, stale, unauthorized,
expired, malformed, or invalid signatures reject. Verification callback failures propagate. The
tracker is in-memory and not concurrency/durability coordination across processes.

## Runtime and scope

Requires WebCrypto for `signApproval`; applications supply an explicit verifier backed by trusted
keys for tracker approvals. No identity directory, certificate trust, timestamping, revocation,
notifications, document locking, or legal-validity determination is included. Approval completion
is an application workflow state only.

## Exports

Runtime: `createApprovalMessage`, `signApproval`, `createApprovalSigningTracker`.
Types: `ApprovalRequest`, `ApprovalSignature`, `ApprovalSigningOptions`, `ApprovalSigningTracker`.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
