/**
 * attestation.ts — Server-side audit logging for legal scope & authorization agreements.
 *
 * Every Deep Scan requires explicit legal attestation under applicable cyber laws
 * (e.g., Section 43/66 of Indian IT Act, US CFAA). Attestations are captured and
 * permanently logged for forensic and compliance auditing.
 */
import { randomUUID } from "node:crypto";

export interface AttestationRecord {
  id: string;
  domain: string;
  userId: string;
  timestamp: string;
  ip: string;
  userAgent: string;
}

const attestationLog: AttestationRecord[] = [];
const MAX_LOG_SIZE = 1000;

export function recordAttestation(params: {
  domain: string;
  userId?: string;
  ip: string;
  userAgent?: string;
}): AttestationRecord {
  const record: AttestationRecord = {
    id: `attest_${randomUUID()}`,
    domain: params.domain.toLowerCase(),
    userId: params.userId || "anonymous",
    timestamp: new Date().toISOString(),
    ip: params.ip,
    userAgent: (params.userAgent || "unknown").slice(0, 256),
  };

  attestationLog.unshift(record);
  if (attestationLog.length > MAX_LOG_SIZE) {
    attestationLog.length = MAX_LOG_SIZE;
  }

  // Structured audit log for compliance / SIEM ingestion
  console.log(
    JSON.stringify({
      evt: "LEGAL_ATTESTATION_RECORDED",
      id: record.id,
      domain: record.domain,
      userId: record.userId,
      ip: record.ip,
      timestamp: record.timestamp,
    })
  );

  return record;
}

export function getAttestationHistory(domain?: string): AttestationRecord[] {
  if (!domain) return [...attestationLog];
  const lower = domain.toLowerCase();
  return attestationLog.filter((a) => a.domain === lower);
}
