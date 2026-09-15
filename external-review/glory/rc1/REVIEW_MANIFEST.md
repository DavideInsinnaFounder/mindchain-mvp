# RC1 Review Manifest

## Identity

REVIEW_ID = GLORY_CRM_DISCOUNT_POC_V1_2_RC1  
PROJECT = VectorRail  
PURPOSE = Independent external technical review  
SOURCE_TAG = glory-poc-v1.2-external-review-rc1  
SOURCE_COMMIT = 2606358ab9a591b67f047a3b9a84032d2b5ffc9e  
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
EXECUTABLE_EXPORT_READY = NO  
DEPENDENCY_CLOSURE_REVIEW_REQUIRED = YES  
MINIMUM_DISCLOSURE_REVIEW_REQUIRED = YES
