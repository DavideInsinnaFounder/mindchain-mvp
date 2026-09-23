# RC1 Review Manifest

## Identity

REVIEW_ID = GLORY_CRM_DISCOUNT_POC_V1_2_RC1  
PROJECT = VectorRail  
PURPOSE = Independent external technical review  
SOURCE_TAG = glory-poc-v1.2-external-review-rc1  
SOURCE_TAG_OBJECT = 183bfa35b2ba4e96b5b20ab605fa3323e5b97bc7
SOURCE_TAG_SIGNED = NO
SOURCE_COMMIT = 2606358ab9a591b67f047a3b9a84032d2b5ffc9e  
SOURCE_TREE = 2851356d28711fcfee30c201724caea00fec3e7f
SOURCE_BOUNDARY = frozen V1.2  
SOURCE_COMMIT_TITLE = feat: add executable Glory acceptance harness

## Integrity facts verified before export

TAG_RESOLVES_TO_SOURCE_COMMIT = YES  
SOURCE_BRANCH = poc/glory-v1-2-minimum-build  
SOURCE_BRANCH_HEAD_EQUALS_TAG = YES  
SOURCE_BRANCH_HEAD_EQUALS_SOURCE_COMMIT = YES  
CANDIDATE_MODIFIED_DURING_RECOVERY = NO

## Review discipline

The reviewer should:

- use only the declared frozen V1.2 boundary;
- treat missing dependencies or ambiguity as findings rather than assumptions;
- distinguish implementation failure, specification failure and model failure;
- attempt to obtain FAIL before accepting a critical PASS;
- tie every substantive finding back to this RC1 identity.

## Disclosure boundary

IN_SCOPE:
- bounded Glory CRM Discount POC material required for review;
- RC1 run instructions;
- RC1 acceptance/adversarial tests;
- required review documentation;
- only the dependency subset necessary to execute the bounded POC.

OUT_OF_SCOPE:
- private VectorRail engineering repository as a whole;
- Token T4 and unrelated formal work;
- private roadmap and commercial material;
- credentials, secrets and private keys;
- unrelated POCs or experimental branches;
- production claims not represented by RC1.

## Export status

PUBLIC_METADATA_READY = YES  
EXECUTABLE_EXPORT_READY = YES
DEPENDENCY_CLOSURE = VERIFIED
UNRESOLVED_INTERNAL_DEPENDENCIES = 0
SOURCE_BYTE_PROVENANCE = PASS
SECRET_SCAN = PASS
DISCLOSURE_SCAN = PASS
REPRODUCIBILITY = PASS
RC1_SEMANTICS_MODIFIED = NO
EXTERNAL_REVIEW_COMPLETED = NO
EXTERNAL_REVIEW_PASS = NOT CLAIMED

## Public executable freeze

PUBLIC_EXECUTABLE_PATH = external-review/glory/rc1/executable/
PUBLIC_EXECUTABLE_COMMIT = 19b904f533604921ae9abbcad654e975e719218c
PUBLIC_FREEZE_TAG = glory-poc-v1.2-external-review-rc1-executable-export
PUBLIC_FREEZE_TAG_OBJECT = f6688c70ceb893d5ea03db60d914bea84800001f
PUBLIC_FREEZE_TAG_SIGNED = NO
PUBLIC_FREEZE_TAG_TARGET = 19b904f533604921ae9abbcad654e975e719218c

The follow-up commit that contains this section is metadata-only. It does not
change any byte under `external-review/glory/rc1/executable/` and does not
change `REVIEW_SCOPE.md`.
