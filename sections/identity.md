# Identity - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#identity)

> **Prerequisites:** [Authentication](authentication.md)  
> **Difficulty:** Intermediate

---

## Table of Contents

1. [Access Control Lists (ACLs)](#access-control-lists-acls)
2. [Service Accounts vs User Accounts](#service-accounts-vs-user-accounts)
3. [Impersonation](#impersonation)
4. [Federated Identity](#federated-identity)
5. [Key Takeaways](#key-takeaways)
6. [Interview Practice Questions](#interview-practice-questions)

---

## Access Control Lists (ACLs)

### Explanation

An Access Control List (ACL) is a data structure that enumerates which authenticated principals (users, groups, service accounts) are permitted or denied specific operations on a given resource. ACLs are one of the oldest authorization mechanisms in computing, dating back to early operating systems and file systems. Each entry in an ACL, called an Access Control Entry (ACE), pairs an identity with a set of permissions such as read, write, execute, or delete. When a subject requests access to an object, the system evaluates the ACL attached to that object to determine whether the request should be granted or denied.

ACLs exist in two primary forms: discretionary access control lists (DACLs) and system access control lists (SACLs). DACLs define who can access a resource, while SACLs define what audit events should be logged when access is attempted. In cloud environments, ACLs appear in network configurations (security groups, network ACLs), storage systems (S3 bucket ACLs, GCS ACLs), and identity platforms. The evaluation order of ACL entries matters significantly -- most systems process deny rules before allow rules, and a missing entry typically results in an implicit deny.

Modern cloud platforms have largely moved toward policy-based access control (PBAC) and role-based access control (RBAC) as supplements or replacements for pure ACLs. However, ACLs remain a foundational concept. AWS VPC Network ACLs are stateless and evaluate rules in numbered order, while Security Groups are stateful. GCP firewall rules operate similarly. Understanding how ACLs interact with higher-level authorization systems is critical for security engineering.

### How It Works

1. **Resource creation** -- When a resource is created (file, bucket, network subnet), an ACL is either explicitly attached or inherited from a parent/default policy.
2. **Principal identification** -- The requesting entity is authenticated and its identity (user ID, group memberships, roles) is established.
3. **ACL lookup** -- The system retrieves the ACL associated with the target resource.
4. **Entry evaluation** -- Each ACE is evaluated against the principal's identity. Deny entries are typically evaluated first.
5. **Permission matching** -- The requested operation (read, write, list, delete) is matched against the permissions granted or denied in the matching ACE.
6. **Decision** -- If an explicit allow is found and no deny overrides it, access is granted. If no matching entry exists, access is implicitly denied.
7. **Audit logging** -- If SACLs are configured, the access attempt (success or failure) is logged for monitoring and compliance.

### Real-World Example

In 2017, numerous S3 bucket data breaches occurred because organizations left bucket ACLs set to "public" or "authenticated AWS users" (which means any AWS account, not just users in your organization). The Booz Allen Hamilton breach exposed Department of Defense data, and the Verizon breach exposed 14 million customer records. These were all caused by misconfigured S3 ACLs that granted overly permissive access. AWS has since introduced S3 Block Public Access as a guardrail, and new buckets default to private.

### Code/Config Example

**AWS S3 Bucket ACL Policy (JSON):**

```json
{
  "AccessControlPolicy": {
    "Owner": {
      "ID": "a]1b2c3d4e5f6...",
      "DisplayName": "bucket-owner"
    },
    "Grants": [
      {
        "Grantee": {
          "Type": "CanonicalUser",
          "ID": "x9y8z7w6v5u4..."
        },
        "Permission": "READ"
      },
      {
        "Grantee": {
          "Type": "Group",
          "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
        },
        "Permission": "WRITE"
      }
    ]
  }
}
```

**AWS VPC Network ACL (Terraform):**

```hcl
resource "aws_network_acl_rule" "allow_https_inbound" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "deny_all_inbound" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 200
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}
```

**Linux File ACL (POSIX):**

```bash
# View ACL on a file
getfacl /var/log/app/secure.log

# Grant read access to the auditors group
setfacl -m g:auditors:r /var/log/app/secure.log

# Remove a specific ACL entry
setfacl -x u:contractor /var/log/app/secure.log
```

### Attack Vectors

- **Overly permissive defaults** -- Cloud resources created with public or broad ACLs. S3 buckets set to `public-read` or GCS buckets with `allUsers` access.
- **ACL inheritance abuse** -- Child resources inheriting overly broad permissions from parent directories or organizational units.
- **Rule order manipulation** -- In numbered ACL systems (VPC NACLs), inserting a low-numbered allow rule before a higher-numbered deny rule.
- **ACL enumeration** -- Attackers probe ACLs to discover which principals have access, mapping out the authorization topology of an organization.
- **Confused deputy via ACL grants** -- Granting a trusted service write access to an ACL, then exploiting that service to modify the ACL itself.

### Best Practices

- **Default deny** -- Always start from a position of no access and explicitly grant only what is required.
- **Prefer RBAC/PBAC over raw ACLs** -- Use IAM roles and policies rather than per-resource ACLs when the platform supports it.
- **Block public access at the account level** -- Enable S3 Block Public Access, GCS uniform bucket-level access, and similar guardrails.
- **Audit ACLs regularly** -- Use tools like AWS Access Analyzer, GCP IAM Recommender, or open-source scanners (Prowler, ScoutSuite) to detect overly permissive ACLs.
- **Use infrastructure-as-code** -- Define ACLs in Terraform or CloudFormation to ensure they are version-controlled and peer-reviewed.
- **Separate network ACLs from application ACLs** -- Defense in depth means layering both network-level and resource-level access controls.

### Interview Tip

> When discussing ACLs, distinguish between network ACLs and resource ACLs. Interviewers want to see that you understand the layered nature of access control. Mention the principle of least privilege and explain how ACLs differ from RBAC -- ACLs are resource-centric (who can access this object?) while RBAC is role-centric (what can this role do?). Bring up real-world S3 bucket breaches to demonstrate applied knowledge.

### References

- [AWS S3 ACL Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
- [AWS VPC Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [GCP Cloud Storage ACLs](https://cloud.google.com/storage/docs/access-control/lists)
- [NIST SP 800-162: Guide to ABAC](https://csrc.nist.gov/publications/detail/sp/800-162/final)

---

## Service Accounts vs User Accounts

### Explanation

Service accounts are non-human identities used by applications, virtual machines, containers, and automation pipelines to authenticate to APIs and services. Unlike user accounts, which represent individual humans and typically authenticate via passwords or MFA, service accounts authenticate using API keys, certificates, OAuth client credentials, or workload identity federation. In GCP, service accounts are a first-class resource type with their own email addresses (e.g., `my-service@project-id.iam.gserviceaccount.com`). In AWS, the equivalent concept is IAM roles assumed by services, EC2 instance profiles, or ECS task roles.

The security implications of service accounts are significant. They often accumulate permissions over time ("privilege creep") because they are created for specific tasks but never cleaned up. They frequently run with standing privileges rather than just-in-time access. In cloud environments, attackers specifically target service accounts because they often have broad permissions, lack MFA, and their credentials can be extracted from metadata services, configuration files, or environment variables. The 2020 SolarWinds attack leveraged compromised service account tokens to move laterally across Azure AD environments.

A critical distinction is between default service accounts and custom service accounts. GCP Compute Engine and App Engine create default service accounts with the Editor role -- far too permissive for most workloads. AWS similarly provisions roles with broad policies if not carefully scoped. Best practice is to always create dedicated, minimally-privileged service accounts for each workload and to disable or restrict default service accounts.

### How It Works

1. **Account creation** -- An administrator creates a service account with a descriptive name and purpose documentation.
2. **Permission assignment** -- IAM policies bind specific roles or permissions to the service account, following least privilege.
3. **Credential issuance** -- The service account receives credentials: a key file (JSON/P12), or is configured for keyless authentication via workload identity.
4. **Workload binding** -- The service account is attached to a compute resource (VM, container, function) or referenced in application configuration.
5. **Token acquisition** -- At runtime, the workload requests an access token from the platform's metadata service or credentials library.
6. **API authentication** -- The token is included in API requests. The receiving service validates the token and evaluates IAM policies.
7. **Token rotation** -- Platform-managed credentials rotate automatically. User-managed keys must be rotated manually on a defined schedule.
8. **Monitoring and auditing** -- All actions performed by the service account are logged in audit logs (CloudTrail, Cloud Audit Logs).

### Real-World Example

In 2021, a misconfigured GCP service account key was committed to a public GitHub repository by a developer at a financial services company. The key belonged to a service account with `roles/owner` on a production project. Automated scanners (both attacker bots and security tools like GitHub's secret scanning) detected the key within minutes. The attacker used the key to enumerate all resources in the project, exfiltrate data from Cloud Storage, and create new compute instances for cryptocurrency mining. The incident cost the company over $50,000 in compute charges and triggered a data breach notification.

### Code/Config Example

**GCP: Create and bind a minimal service account (gcloud):**

```bash
# Create a dedicated service account
gcloud iam service-accounts create data-pipeline-sa \
  --display-name="Data Pipeline Service Account" \
  --description="Reads from input bucket, writes to output bucket"

# Grant only the specific permissions needed
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:data-pipeline-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer" \
  --condition='expression=resource.name.startsWith("projects/_/buckets/input-bucket"),title=InputBucketOnly'

gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:data-pipeline-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectCreator" \
  --condition='expression=resource.name.startsWith("projects/_/buckets/output-bucket"),title=OutputBucketOnly'

# Attach to a GKE workload via Workload Identity (keyless)
kubectl annotate serviceaccount data-pipeline-ksa \
  --namespace=pipelines \
  iam.gke.io/gcp-service-account=data-pipeline-sa@my-project.iam.gserviceaccount.com
```

**AWS: IAM Role for Lambda function (CloudFormation):**

```yaml
Resources:
  DataProcessorRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: data-processor-lambda-role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: MinimalS3Access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                Resource: arn:aws:s3:::input-bucket/*
              - Effect: Allow
                Action:
                  - s3:PutObject
                Resource: arn:aws:s3:::output-bucket/*
              - Effect: Deny
                Action:
                  - s3:DeleteObject
                  - s3:PutBucketPolicy
                Resource: "*"
```

### Attack Vectors

- **Key exfiltration** -- Extracting service account keys from metadata endpoints (169.254.169.254), environment variables, or committed secrets in version control.
- **Privilege escalation via default accounts** -- Exploiting default service accounts that carry `Editor` or `Owner` roles.
- **Lateral movement** -- Compromising one service account to access resources that provide credentials for other service accounts.
- **Token theft from metadata service** -- SSRF vulnerabilities in applications running on cloud VMs can be exploited to retrieve service account tokens from the instance metadata service.
- **Persistence via key creation** -- An attacker with `iam.serviceAccountKeys.create` permission can generate new keys for existing service accounts, establishing persistent access.
- **Cloud shell / console impersonation** -- Attackers use stolen service account credentials to authenticate via CLI tools, bypassing typical user-facing security controls.

### Best Practices

- **Eliminate user-managed keys** -- Use workload identity, instance metadata, or federated tokens instead of exported JSON key files.
- **Disable default service accounts** -- Apply an organization policy constraint (`iam.automaticIamGrantsForDefaultServiceAccounts`) to prevent default SA privilege grants.
- **Enforce key rotation** -- If keys are unavoidable, rotate them every 90 days and alert on keys older than that threshold.
- **Use IAM conditions** -- Scope service account permissions by resource, time, IP, or other attributes.
- **Monitor service account usage** -- Alert on anomalous behavior: access from unexpected IPs, use of dormant accounts, or privilege escalation attempts.
- **Implement service account lifecycle management** -- Regularly review, disable unused accounts, and require justification for high-privilege service accounts.

### Interview Tip

> Emphasize the difference between platform-managed and user-managed credentials. Show that you understand why keyless authentication (workload identity, instance profiles) is strongly preferred. Mention SSRF-to-metadata-service attacks as a concrete threat model. If asked about incident response, explain how you would identify all resources a compromised service account could access by analyzing IAM policy bindings.

### References

- [GCP Service Accounts Overview](https://cloud.google.com/iam/docs/service-accounts)
- [GCP Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [AWS IAM Roles for Services](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [AWS Instance Metadata Service v2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Impersonation

### Explanation

Impersonation in identity systems refers to the ability of one principal to act as (assume the identity of) another principal. In cloud environments, this is a designed feature -- GCP's `serviceAccountTokenCreator` role and AWS's `sts:AssumeRole` mechanism both provide controlled impersonation. When properly configured, impersonation enables least-privilege workflows: instead of granting a developer permanent access to production resources, you allow them to impersonate a production service account on demand, with full audit logging. The impersonating identity's original identity is preserved in audit logs alongside the impersonated identity.

However, impersonation becomes a critical attack vector when misconfigured. If an attacker gains access to a principal that can impersonate high-privilege service accounts, they effectively inherit all of those accounts' permissions. In GCP, the `iam.serviceAccounts.actAs` permission is required to deploy resources (Cloud Functions, Compute Engine) that run as a service account. If this permission is granted too broadly, a developer who can deploy code can effectively become any service account. Similarly, exported service account keys (JSON key files) allow permanent impersonation from any location without MFA, IP restrictions, or session controls.

JWT (JSON Web Token) based impersonation is particularly relevant in cloud and microservices architectures. GCP issues OAuth 2.0 access tokens and OpenID Connect ID tokens for service accounts. An attacker who can forge or steal these JWTs can impersonate the service account until the token expires. AWS STS tokens work similarly, providing temporary credentials that represent an assumed role. Understanding token lifetimes, refresh mechanisms, and revocation capabilities is essential for defending against impersonation attacks.

### How It Works

1. **Permission grant** -- An administrator grants impersonation permissions (e.g., `roles/iam.serviceAccountTokenCreator` in GCP or a trust policy in AWS) to the source principal.
2. **Impersonation request** -- The source principal requests to act as the target identity, providing justification or meeting conditions (IP range, time window).
3. **Policy evaluation** -- The platform evaluates whether the source principal has the necessary impersonation permission on the target identity.
4. **Token generation** -- If authorized, the platform generates a short-lived token (access token, session credentials) representing the target identity.
5. **Delegated action** -- The source principal uses the generated token to make API calls as the target identity.
6. **Audit trail** -- Both the original caller and the impersonated identity are recorded in audit logs, creating accountability.
7. **Token expiration** -- The impersonation token expires after a configured lifetime (default 1 hour in most platforms), requiring re-authorization.

### Real-World Example

In a 2022 cloud security assessment, researchers demonstrated a GCP privilege escalation chain. A developer with `iam.serviceAccounts.actAs` on a Compute Engine default service account and `compute.instances.create` permission could launch a VM running as the default service account (which had `Editor` role). From the VM, they accessed the metadata service to obtain the service account's access token, then used that token to escalate to project-level editor access. This "token hopping" technique exploits the combination of impersonation permissions and overly privileged service accounts.

### Code/Config Example

**GCP: Service Account Impersonation:**

```bash
# Grant impersonation permission to a user
gcloud iam service-accounts add-iam-policy-binding \
  target-sa@my-project.iam.gserviceaccount.com \
  --member="user:developer@company.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Generate an impersonated access token
gcloud auth print-access-token \
  --impersonate-service-account=target-sa@my-project.iam.gserviceaccount.com

# Use impersonation in Terraform
provider "google" {
  impersonate_service_account = "deploy-sa@my-project.iam.gserviceaccount.com"
}
```

**AWS: AssumeRole for Cross-Account Access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/developer-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

**JWT Token Structure (Decoded GCP ID Token):**

```json
{
  "header": {
    "alg": "RS256",
    "kid": "key-id-from-jwks-endpoint",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://accounts.google.com",
    "azp": "target-sa@my-project.iam.gserviceaccount.com",
    "aud": "https://my-api.example.com",
    "sub": "1234567890",
    "email": "target-sa@my-project.iam.gserviceaccount.com",
    "email_verified": true,
    "iat": 1672531200,
    "exp": 1672534800
  },
  "signature": "base64url-encoded-RS256-signature"
}
```

**Python: Detect and validate impersonation tokens:**

```python
from google.auth import impersonated_credentials
from google.oauth2 import service_account
import google.auth

# Legitimate impersonation flow with audit trail
source_credentials, project = google.auth.default()

target_credentials = impersonated_credentials.Credentials(
    source_credentials=source_credentials,
    target_principal="target-sa@my-project.iam.gserviceaccount.com",
    target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    lifetime=3600  # 1 hour max
)

# Use target_credentials for API calls -- audit logs will show both identities
```

### Attack Vectors

- **Exported key abuse** -- Stolen JSON key files provide indefinite impersonation capability. Keys don't expire and don't require MFA.
- **ActAs privilege escalation** -- Gaining `iam.serviceAccounts.actAs` allows launching workloads as high-privilege service accounts.
- **Token theft via SSRF** -- Server-side request forgery to cloud metadata endpoints yields short-lived impersonation tokens.
- **JWT confusion attacks** -- Algorithm confusion (changing RS256 to HS256) or key injection in JWT headers to forge valid tokens.
- **Cross-account role chaining** -- Abusing overly permissive AssumeRole trust policies to chain through multiple accounts.
- **Token lifetime exploitation** -- If token lifetimes are set too long, stolen tokens remain valid for extended periods after credential rotation.
- **Delegation chain abuse** -- In GCP, delegated impersonation (SA-A impersonates SA-B who impersonates SA-C) creates complex chains that are hard to audit.

### Best Practices

- **Eliminate exported keys** -- Use workload identity and short-lived tokens instead of persistent key files.
- **Scope impersonation narrowly** -- Grant `serviceAccountTokenCreator` only on specific service accounts, never at the project or organization level.
- **Set short token lifetimes** -- Configure the minimum viable token lifetime for impersonated credentials.
- **Monitor impersonation events** -- Alert on `GenerateAccessToken`, `GenerateIdToken`, and `AssumeRole` events in audit logs.
- **Require conditions on AssumeRole** -- Use ExternalId, source IP, and MFA conditions on AWS trust policies.
- **Audit actAs permissions regularly** -- The `actAs` permission is often overlooked in IAM reviews but is one of the most powerful permissions in GCP.
- **Implement token binding** -- Where possible, bind tokens to specific clients or network contexts to prevent replay.

### Interview Tip

> Impersonation is a nuanced topic that separates strong candidates. Explain that impersonation is a legitimate security pattern (short-lived, auditable, conditional) when contrasted with standing access via exported keys. Walk through a specific privilege escalation scenario: "If I have actAs on a service account with Editor role, plus compute.instances.create, I can escalate to Editor." This demonstrates both offensive and defensive thinking.

### References

- [GCP Service Account Impersonation](https://cloud.google.com/iam/docs/impersonating-service-accounts)
- [GCP Understanding actAs](https://cloud.google.com/iam/docs/understanding-roles#service-accounts-roles)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [GCP Privilege Escalation Research - Rhino Security Labs](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)

---

## Federated Identity

### Explanation

Federated identity enables users authenticated by one identity provider (IdP) to access resources managed by a different organization or platform without creating a separate set of credentials. The core idea is trust delegation: a service provider (SP) trusts an external IdP to perform authentication, and the IdP provides assertions (SAML assertions, OIDC tokens, or WS-Federation claims) that the SP uses for authorization decisions. This eliminates credential sprawl -- users maintain a single identity (typically their corporate identity) and use it across multiple systems and cloud providers.

In cloud environments, federation takes several forms. SAML 2.0 federation allows enterprise IdPs (Okta, Azure AD, Ping Identity) to provide SSO into AWS, GCP, and Azure consoles. OIDC federation enables workloads running outside a cloud provider (GitHub Actions, GitLab CI, on-premises servers) to authenticate without static credentials through workload identity federation. AWS supports SAML and OIDC federation via IAM Identity Providers, while GCP supports these via Workload Identity Pools and Workforce Identity Federation.

The security model of federated identity relies on the integrity of the trust relationship between the SP and IdP. If the IdP is compromised, all SPs that trust it are affected. The 2020 SolarWinds/Solorigate attack demonstrated this catastrophically: attackers compromised on-premises Active Directory Federation Services (AD FS) and forged SAML tokens (a "golden SAML" attack) to gain persistent access to Azure AD and all federated cloud resources. Understanding the trust boundaries, token validation, and failure modes of federation protocols is essential for security engineers.

### How It Works

1. **Trust establishment** -- The SP and IdP exchange metadata: the IdP provides its signing certificate and token endpoint; the SP provides its entity ID and assertion consumer URL.
2. **User initiates access** -- A user navigates to the SP or a federated login page and selects their IdP.
3. **Authentication at IdP** -- The user authenticates with the IdP using their corporate credentials and MFA.
4. **Assertion generation** -- The IdP creates a signed assertion (SAML assertion or OIDC ID token) containing the user's identity, attributes, and group memberships.
5. **Assertion delivery** -- The assertion is sent to the SP, either via browser redirect (SAML) or direct token exchange (OIDC).
6. **Assertion validation** -- The SP validates the assertion's signature, issuer, audience, timestamps, and any conditions.
7. **Attribute mapping** -- The SP maps attributes from the assertion (groups, roles, email) to local authorization constructs (IAM roles, permissions).
8. **Session creation** -- The SP creates a local session with the mapped permissions. The session has its own lifetime, independent of the IdP session.
9. **Continuous evaluation** -- Modern systems may re-evaluate the user's posture during the session (device trust, network location) via continuous access evaluation.

### Real-World Example

In the SolarWinds/Solorigate attack (disclosed December 2020), the threat actor UNC2452/Nobelium compromised on-premises AD FS servers and extracted the token-signing certificate. With this certificate, they forged SAML assertions for any user, including those with Global Administrator roles in Azure AD. This "golden SAML" attack provided persistent, undetectable access to Microsoft 365, Azure, and any application federated with the compromised AD FS. The attackers maintained access for months, reading emails and exfiltrating data. This attack fundamentally changed how organizations think about federation trust: the on-premises AD FS server became the single point of failure for the entire cloud identity architecture.

### Code/Config Example

**AWS: SAML Federation Provider Setup (CloudFormation):**

```yaml
Resources:
  SAMLProvider:
    Type: AWS::IAM::SAMLProvider
    Properties:
      Name: CorporateIdP
      SamlMetadataDocument: |
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
          entityID="https://idp.company.com/saml">
          <!-- IdP metadata with signing certificate -->
        </EntityDescriptor>

  FederatedAdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: FederatedCloudAdmin
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Ref SAMLProvider
            Action: sts:AssumeRoleWithSAML
            Condition:
              StringEquals:
                "SAML:aud": "https://signin.aws.amazon.com/saml"
              ForAnyValue:StringLike:
                "SAML:groups": "cloud-admins"
```

**GCP: Workload Identity Federation for GitHub Actions:**

```bash
# Create a Workload Identity Pool
gcloud iam workload-identity-pools create github-pool \
  --location="global" \
  --display-name="GitHub Actions Pool"

# Create a provider for GitHub OIDC
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository_owner=='my-org'"

# Grant the external identity permission to impersonate a service account
gcloud iam service-accounts add-iam-policy-binding \
  deploy-sa@my-project.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/github-pool/attribute.repository/my-org/my-repo"
```

**GitHub Actions Workflow Using OIDC Federation:**

```yaml
jobs:
  deploy:
    permissions:
      contents: read
      id-token: write  # Required for OIDC token request
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: "projects/123/locations/global/workloadIdentityPools/github-pool/providers/github-provider"
          service_account: "deploy-sa@my-project.iam.gserviceaccount.com"
      - uses: google-github-actions/setup-gcloud@v2
      - run: gcloud storage cp ./build gs://my-deploy-bucket/
```

**SAML Assertion Structure (Simplified):**

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_abc123" IssueInstant="2026-04-12T10:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.company.com/saml</saml:Issuer>
  <ds:Signature><!-- XML Digital Signature --></ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">
      user@company.com
    </saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="2026-04-12T10:00:00Z"
                   NotOnOrAfter="2026-04-12T10:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>urn:amazon:webservices</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
      <saml:AttributeValue>
        arn:aws:iam::123456789012:role/FederatedAdmin,arn:aws:iam::123456789012:saml-provider/CorporateIdP
      </saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### Attack Vectors

- **Golden SAML** -- Compromising the IdP's token-signing certificate to forge arbitrary SAML assertions for any user with any role.
- **OIDC claim injection** -- Manipulating OIDC token claims (e.g., repository name in GitHub Actions) to bypass attribute conditions on workload identity pools.
- **IdP compromise** -- Gaining administrative access to the IdP (Okta, Azure AD) grants implicit access to all federated SPs.
- **Assertion replay** -- Capturing and replaying valid SAML assertions or OIDC tokens before they expire.
- **XML signature wrapping** -- Manipulating the XML structure of SAML assertions so the signature validates on a different element than what the SP processes.
- **Audience restriction bypass** -- SAML assertions or OIDC tokens accepted by SPs that are not the intended audience due to missing audience validation.
- **Attribute mapping exploitation** -- Abusing how IdP attributes are mapped to SP roles to gain unintended privilege (e.g., adding yourself to a group that maps to `Admin` in AWS).

### Best Practices

- **Protect IdP signing keys as crown jewels** -- Store SAML/OIDC signing certificates in HSMs, rotate them regularly, and monitor for unauthorized access.
- **Enforce short assertion lifetimes** -- SAML assertions should be valid for minutes, not hours. OIDC tokens should have short expiry.
- **Validate all assertion fields** -- Always check issuer, audience, signature, timestamps, and conditions. Never skip validation.
- **Use attribute conditions on workload identity** -- In GCP Workload Identity Pools and AWS OIDC providers, restrict which external identities can federate using attribute conditions.
- **Monitor federation events** -- Alert on SAML assertion generation, especially for privileged roles, unusual times, or unfamiliar source IPs.
- **Consider moving to cloud-native IdP** -- Migrating from on-premises AD FS to cloud-managed solutions (Azure AD, Google Workspace) reduces the attack surface of the golden SAML vector.
- **Implement break-glass procedures** -- Maintain non-federated emergency access accounts in case the IdP is compromised or unavailable.

### Interview Tip

> Federation questions test your understanding of trust boundaries. The key insight is that federation shifts the security perimeter to the IdP -- whoever controls the IdP controls access to every federated service. Mention the golden SAML attack as a concrete example. For bonus points, explain the difference between SAML (XML-based, browser-redirect flow, enterprise SSO) and OIDC (JSON/JWT-based, more modern, better for APIs and workload identity), and when you would use each.

### References

- [AWS IAM Identity Providers (SAML/OIDC)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [GCP Workforce Identity Federation](https://cloud.google.com/iam/docs/workforce-identity-federation)
- [SAML 2.0 Technical Overview (OASIS)](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [NIST SP 800-63C: Federation and Assertions](https://pages.nist.gov/800-63-3/sp800-63c.html)
- [Microsoft: Golden SAML Attack Detection](https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)

---

## Key Takeaways

- **ACLs are foundational but insufficient alone** -- Combine them with RBAC, PBAC, and IAM policies for defense in depth. Always default to deny.
- **Service accounts are high-value targets** -- Eliminate exported keys, use workload identity, enforce least privilege, and monitor for anomalous usage. Disable default service accounts.
- **Impersonation is a feature and a risk** -- When properly scoped with short-lived tokens and audit logging, impersonation is more secure than standing access. When misconfigured, it enables privilege escalation chains.
- **Federation centralizes trust in the IdP** -- Protect the IdP and its signing keys as the most critical assets in your identity architecture. A compromised IdP means total compromise of all federated services.
- **Identity is the new perimeter** -- In cloud-native and zero-trust architectures, identity and access management replaces network perimeter as the primary security control plane.

## Interview Practice Questions

1. **Scenario:** You discover that a GCP project has 15 service accounts, 10 of which have exported JSON keys. Six of those keys are over a year old. Walk the interviewer through your remediation plan.

2. **Design:** How would you architect identity and access management for a company migrating from on-premises to a multi-cloud environment (AWS + GCP)? What federation model would you use?

3. **Incident Response:** Your SIEM alerts on a service account generating access tokens from an IP address in a country where your company has no operations. What is your investigation and response playbook?

4. **Deep Dive:** Explain the difference between `iam.serviceAccounts.actAs` and `iam.serviceAccountTokenCreator` in GCP. Why is `actAs` considered more dangerous?

5. **Attack Analysis:** Describe the golden SAML attack. What prerequisites does an attacker need? How would you detect it, and what architectural changes would prevent it?

6. **Trade-offs:** When would you choose SAML federation over OIDC for cloud access? What are the security trade-offs of each protocol?

7. **Coding:** Write a script that audits all service accounts in a GCP organization, identifies those with exported keys older than 90 days, and generates a report of associated IAM bindings.

---

[Previous: Authentication](authentication.md) | [Next: Malware & Reversing](malware-reversing.md)
