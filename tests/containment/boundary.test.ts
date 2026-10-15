import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createGloryPocRuntime,createGloryDemoIntent} from '../../src/poc/glory/poc.js';
import {deriveAuthorizationProofId,snapshotAuthorizationProof} from '../../src/review/authorization_proof.js';

test('concurrent same-authorization execution dispatches once',async()=>{
 const r=createGloryPocRuntime(),a=r.authorize(createGloryDemoIntent(700));
 const results=await Promise.all(Array.from({length:32},()=>r.execute(a.authorization_attempt_id)));
 assert.equal(results.filter(x=>x.authorization_evidence.guard_result==='PASS').length,1);
 assert.equal(results.filter(x=>x.authorization_evidence.guard_reason==='authorization_replay').length,31);
 assert.equal(r.getRequestCount(),1);assert.equal(r.getEffectCount(),1);
});
test('concurrent indeterminate execution has one request and no retry',async()=>{
 const r=createGloryPocRuntime({downstreamMode:'timeout_after_effect'}),a=r.authorize(createGloryDemoIntent(700));
 const results=await Promise.all(Array.from({length:32},()=>r.execute(a.authorization_attempt_id)));
 assert.equal(results.filter(x=>x.determination==='REQUIRES_DETERMINATION').length,1);
 assert.equal(r.getRequestCount(),1);assert.equal(r.getEffectCount(),1);
});
test('unsupported scopes and unknown fields fail closed',()=>{
 const r=createGloryPocRuntime(),a=r.authorize(createGloryDemoIntent(700));
 const mutations=[(p:any)=>p.payload.economic_scope={mode:'bounded'},(p:any)=>p.payload.execution_scope={mode:'bounded'},(p:any)=>p.payload.usage={mode:'bounded',maximum_usage_count:2},(p:any)=>p.payload.provider_scope={mode:'any_authorized'},(p:any)=>p.payload.extra_authority=true,(p:any)=>p.extra_authority=true];
 for(const mutate of mutations){const p=structuredClone(a.proof!);mutate(p);assert.throws(()=>snapshotAuthorizationProof(p));assert.notEqual(r.verifyProof(p).verification,'verified_locally');}
});
test('payload accessors are rejected without evaluation',()=>{
 const r=createGloryPocRuntime(),a=r.authorize(createGloryDemoIntent(700)),p=structuredClone(a.proof!);let reads=0;
 Object.defineProperty(p.payload,'principal_id',{enumerable:true,get(){reads++;return 'principal-demo-001';}});
 assert.throws(()=>snapshotAuthorizationProof(p));assert.equal(reads,0);
});
test('decision substitution after recomputing identity still fails signature',()=>{
 const r=createGloryPocRuntime(),a=r.authorize(createGloryDemoIntent(700)),p=structuredClone(a.proof!);
 p.payload.authorization_decision_id='attacker';p.proof_id=deriveAuthorizationProofId(p.payload);
 assert.deepEqual(r.verifyProof(p),{verification:'not_verified',reason:'invalid_signature'});
});
test('cross-runtime key substitution fails before dispatch',async()=>{
 const a=createGloryPocRuntime(),b=createGloryPocRuntime();const aa=a.authorize(createGloryDemoIntent(700)),bb=b.authorize(createGloryDemoIntent(700));
 const result=await b.execute(bb.authorization_attempt_id,{proof:aa.proof});
 assert.equal(result.authorization_evidence.guard_result,'BLOCK');assert.equal(b.getRequestCount(),0);assert.equal(b.getEffectCount(),0);
});
