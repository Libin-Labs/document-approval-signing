export interface ApprovalRequest {
  id: string;
  revision: number;
  digest: Uint8Array;
  expiresAt: number;
}

export interface ApprovalSignature {
  approver: string;
  revision: number;
  digest: Uint8Array;
  signature: Uint8Array;
}

export interface ApprovalSigningOptions extends ApprovalRequest {
  approvers: readonly string[];
  requiredApprovals?: number;
  verify: (approver: string, message: Uint8Array, signature: Uint8Array) => Promise<boolean>;
}

export interface ApprovalSigningTracker {
  readonly status: 'pending' | 'approved' | 'expired';
  approve(input: ApprovalSignature, now?: number): Promise<'pending' | 'approved'>;
  snapshot(): { status: 'pending' | 'approved' | 'expired'; approvals: readonly string[] };
}

const encoder = new TextEncoder();

function source(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function label(value: string, name: string): void {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256)
    throw new TypeError(`${name} must contain 1 to 256 characters.`);
}

function requestValue(request: ApprovalRequest): ApprovalRequest {
  label(request.id, 'Request ID');
  if (!Number.isSafeInteger(request.revision) || request.revision < 0)
    throw new RangeError('Revision must be a nonnegative safe integer.');
  if (!(request.digest instanceof Uint8Array) || request.digest.length !== 32)
    throw new TypeError('Document digest must be a 32-byte SHA-256 digest.');
  if (!Number.isSafeInteger(request.expiresAt) || request.expiresAt < 0)
    throw new RangeError('expiresAt must be a nonnegative Unix timestamp in milliseconds.');
  return {
    id: request.id,
    revision: request.revision,
    digest: new Uint8Array(request.digest),
    expiresAt: request.expiresAt,
  };
}

function frame(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setUint32(0, bytes.length);
  result.set(bytes, 4);
  return result;
}

export function createApprovalMessage(requestInput: ApprovalRequest, approver: string): Uint8Array {
  const request = requestValue(requestInput);
  label(approver, 'Approver');
  const fields = [
    encoder.encode('LP-DOCUMENT-APPROVAL-V1'),
    encoder.encode(request.id),
    encoder.encode(approver),
    encoder.encode(String(request.revision)),
    request.digest,
    encoder.encode(String(request.expiresAt)),
  ].map(frame);
  const message = new Uint8Array(fields.reduce((total, field) => total + field.length, 0));
  let offset = 0;
  for (const field of fields) {
    message.set(field, offset);
    offset += field.length;
  }
  return message;
}

export async function signApproval(
  request: ApprovalRequest,
  approver: string,
  key: CryptoKey,
  algorithm:
    | { name: 'ECDSA'; namedCurve: 'P-256' }
    | { name: 'RSA-PSS'; hash: 'SHA-256'; saltLength?: number },
  subtleInput?: SubtleCrypto,
): Promise<ApprovalSignature> {
  const message = createApprovalMessage(request, approver);
  if (!key || !key.algorithm || !Array.isArray(key.usages))
    throw new TypeError('An approval CryptoKey is required.');
  if (!key.usages.includes('sign')) throw new TypeError('Approval key lacks sign usage.');
  if (
    !algorithm ||
    typeof algorithm !== 'object' ||
    (algorithm.name !== 'ECDSA' && algorithm.name !== 'RSA-PSS')
  )
    throw new TypeError('Only ECDSA P-256 and RSA-PSS SHA-256 are supported.');
  if (algorithm.name === 'ECDSA' && algorithm.namedCurve !== 'P-256')
    throw new TypeError('ECDSA must use P-256.');
  if (
    algorithm.name === 'RSA-PSS' &&
    (algorithm.hash !== 'SHA-256' ||
      (algorithm.saltLength !== undefined &&
        (!Number.isSafeInteger(algorithm.saltLength) ||
          algorithm.saltLength < 0 ||
          algorithm.saltLength > 1024)))
  )
    throw new TypeError('RSA-PSS must use SHA-256 and an integer saltLength from 0 to 1024.');
  const subtle = subtleInput ?? globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.sign !== 'function')
    throw new Error('WebCrypto SubtleCrypto is unavailable.');
  const operation: AlgorithmIdentifier | EcdsaParams | RsaPssParams =
    algorithm.name === 'ECDSA'
      ? { name: 'ECDSA', hash: 'SHA-256' }
      : { name: 'RSA-PSS', saltLength: algorithm.saltLength ?? 32 };
  const signature = new Uint8Array(await subtle.sign(operation, key, source(message)));
  const normalized = requestValue(request);
  return Object.freeze({
    approver,
    revision: normalized.revision,
    digest: normalized.digest,
    signature,
  });
}

export function createApprovalSigningTracker(
  input: ApprovalSigningOptions,
): ApprovalSigningTracker {
  const request = requestValue(input);
  if (typeof input.verify !== 'function')
    throw new TypeError('A signature verifier callback is required.');
  if (
    !Array.isArray(input.approvers) ||
    input.approvers.length < 1 ||
    input.approvers.length > 10_000
  )
    throw new RangeError('Approver list must contain 1 to 10000 entries.');
  const approvers = new Set<string>();
  for (const approver of input.approvers) {
    label(approver, 'Approver');
    if (approvers.has(approver)) throw new TypeError('Approver identities must be unique.');
    approvers.add(approver);
  }
  const threshold = input.requiredApprovals ?? approvers.size;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > approvers.size)
    throw new RangeError('requiredApprovals must be within the approver count.');
  const approvals = new Set<string>();
  const inFlight = new Set<string>();
  let state: 'pending' | 'approved' | 'expired' = 'pending';
  return {
    get status() {
      return state;
    },
    async approve(approval, now = Date.now()) {
      if (state !== 'pending') throw new Error(`Request is ${state}; it cannot accept approvals.`);
      if (!Number.isSafeInteger(now) || now < 0)
        throw new RangeError('now must be a nonnegative safe integer.');
      if (now >= request.expiresAt) {
        state = 'expired';
        throw new Error('Approval request has expired.');
      }
      label(approval.approver, 'Approver');
      if (!approvers.has(approval.approver))
        throw new TypeError('Approver is not authorized by the supplied policy.');
      if (approval.revision !== request.revision || approval.revision !== input.revision)
        throw new Error('Stale approval: document revision does not match the request.');
      if (
        !(approval.digest instanceof Uint8Array) ||
        approval.digest.length !== 32 ||
        approval.digest.some((byte, index) => byte !== request.digest[index])
      )
        throw new Error('Stale approval: document digest does not match the request.');
      if (
        !(approval.signature instanceof Uint8Array) ||
        approval.signature.length < 1 ||
        approval.signature.length > 16_384
      )
        throw new TypeError('Approval signature must contain 1 to 16384 bytes.');
      if (approvals.has(approval.approver) || inFlight.has(approval.approver))
        throw new Error('Approver has already submitted an approval.');
      inFlight.add(approval.approver);
      try {
        const valid = await input.verify(
          approval.approver,
          createApprovalMessage(request, approval.approver),
          new Uint8Array(approval.signature),
        );
        if (valid !== true) throw new Error('Approval signature verification failed.');
        if (state !== 'pending') throw new Error('Approval request is no longer pending.');
        approvals.add(approval.approver);
        if (approvals.size >= threshold) state = 'approved';
        return state === 'approved' ? 'approved' : 'pending';
      } finally {
        inFlight.delete(approval.approver);
      }
    },
    snapshot() {
      if (state === 'pending' && Date.now() >= request.expiresAt) state = 'expired';
      return Object.freeze({ status: state, approvals: Object.freeze([...approvals].sort()) });
    },
  };
}
