/** Review-only process-local one-use gate; no durable or economic contract. */
import type { AuthorizationProof } from './contracts.js';
import { deriveAuthorizationProofId, snapshotAuthorizationProof } from './authorization_proof.js';
export interface AtomicAdmissionAuthority {
  commitAuthorizationAdmission(input: unknown):
    | { admission: 'admission_committed' | 'admission_replayed' }
    | { admission: 'admission_rejected'; failure: { reason: string } };
}
function capture(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid');
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
  if(keys.length!==fields.length||keys.some(k=>typeof k!=='string'||!fields.includes(k)))throw new Error('invalid');
  const result=Object.create(null);
  for(const k of fields){const d=descriptors[k];if(!d||!('value' in d)||'get' in d||'set' in d)throw new Error('invalid');result[k]=d.value;}
  return result;
}
export function createAtomicAdmissionAuthority(): AtomicAdmissionAuthority {
  const admissions=new Map<string,string>(),usedProofs=new Set<string>(),usedDecisions=new Set<string>();
  let preparing=false;
  const reject=(reason: string)=>Object.freeze({admission:'admission_rejected' as const,failure:Object.freeze({reason})});
  return Object.freeze({commitAuthorizationAdmission(input: unknown) {
    if(preparing)return reject('structural_invalid');
    preparing=true;
    try {
      const c=capture(input,['admission_id','proof','local_verification','requested_usage_index','execution_request','economic_request']);
      if(typeof c.admission_id!=='string'||!c.admission_id.trim())return reject('structural_invalid');
      const proof=snapshotAuthorizationProof(c.proof as AuthorizationProof),proofId=deriveAuthorizationProofId(proof.payload);
      if(proof.proof_id!==proofId)return reject('proof_id_mismatch');
      const verification=capture(c.local_verification,['verification','proof_id']);
      if(verification.verification!=='verified_locally'||verification.proof_id!==proofId)return reject('local_verification_rejected');
      const execution=capture(c.execution_request,['mode','execution_attempt_id','operation_type']);
      if(execution.mode!=='exact'||execution.execution_attempt_id!==proof.payload.execution_scope.execution_id||execution.operation_type!==proof.payload.execution_scope.operation_type)return reject('execution_attempt_mismatch');
      const scope=capture(c.economic_request,['mode']);
      if(scope.mode!=='none'||proof.payload.economic_scope.mode!=='none'||c.requested_usage_index!==1||proof.payload.usage.mode!=='single_use')return reject('structural_invalid');
      const fingerprint=JSON.stringify([proofId,proof.payload.authorization_decision_id,execution.execution_attempt_id,execution.operation_type,1]);
      const previous=admissions.get(c.admission_id);
      if(previous!==undefined)return previous===fingerprint?Object.freeze({admission:'admission_replayed' as const}):reject('admission_conflict');
      if(usedProofs.has(proofId)||usedDecisions.has(proof.payload.authorization_decision_id))return reject('proof_usage_rejected');
      // Every check completes synchronously before the single process-local commit.
      admissions.set(c.admission_id,fingerprint);usedProofs.add(proofId);usedDecisions.add(proof.payload.authorization_decision_id);
      return Object.freeze({admission:'admission_committed' as const});
    } catch { return reject('structural_invalid'); }
    finally { preparing=false; }
  }});
}
