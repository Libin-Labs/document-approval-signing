import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  createApprovalMessage,
  createApprovalSigningTracker,
  signApproval,
} from '../dist/esm/index.js';

const request = {
  id: 'release-7',
  revision: 3,
  digest: new Uint8Array(32).fill(8),
  expiresAt: 5000,
};

test('binds signatures to document revision and approver and reaches an explicit quorum', async () => {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const approval = await signApproval(
    request,
    'alice',
    keys.privateKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    webcrypto.subtle,
  );
  const tracker = createApprovalSigningTracker({
    ...request,
    approvers: ['alice', 'bob'],
    requiredApprovals: 1,
    verify: (who, message, signature) =>
      webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keys.publicKey,
        signature,
        message,
      ),
  });
  assert.equal(await tracker.approve(approval, 1000), 'approved');
  assert.equal(tracker.snapshot().status, 'approved');
  assert.notDeepEqual(
    createApprovalMessage(request, 'alice'),
    createApprovalMessage(request, 'bob'),
  );
  const otherRequest = { ...request, id: 'release-8' };
  const crossContext = createApprovalSigningTracker({
    ...otherRequest,
    approvers: ['alice'],
    verify: (_who, message, signature) =>
      webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keys.publicKey,
        signature,
        message,
      ),
  });
  await assert.rejects(crossContext.approve(approval, 1000), /verification failed/);
});

test('stale revision, bad signature, duplicate and unauthorized approval are rejected', async () => {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const good = await signApproval(
    request,
    'alice',
    keys.privateKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    webcrypto.subtle,
  );
  const tracker = createApprovalSigningTracker({
    ...request,
    approvers: ['alice', 'bob'],
    verify: (_who, message, signature) =>
      webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keys.publicKey,
        signature,
        message,
      ),
  });
  await assert.rejects(tracker.approve({ ...good, revision: 2 }, 1000), /Stale/);
  await assert.rejects(
    tracker.approve({ ...good, signature: new Uint8Array([0]) }, 1000),
    /verification/,
  );
  await assert.rejects(tracker.approve({ ...good, approver: 'eve' }, 1000), /not authorized/);
  await tracker.approve(good, 1000);
  await assert.rejects(tracker.approve(good, 1000), /already submitted/);
});

test('expires before accepting approvals and validates quorum configuration', async () => {
  const tracker = createApprovalSigningTracker({
    ...request,
    approvers: ['alice'],
    verify: async () => true,
  });
  await assert.rejects(
    tracker.approve(
      { approver: 'alice', revision: 3, digest: request.digest, signature: new Uint8Array([1]) },
      5000,
    ),
    /expired/,
  );
  assert.equal(tracker.status, 'expired');
  assert.throws(
    () =>
      createApprovalSigningTracker({
        ...request,
        approvers: ['alice'],
        requiredApprovals: 2,
        verify: async () => true,
      }),
    /requiredApprovals/,
  );
});
