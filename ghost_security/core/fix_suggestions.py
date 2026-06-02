"""
fix_suggestions.py — TythanAI Ghost Security Platform
Fix Suggestions Engine

Maps every rule ID (phases 1-10) to a concrete, actionable code fix with
before/after examples, explanations, references, and estimated remediation
effort.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FixSuggestion:
    """
    A single, self-contained remediation record for one security rule.

    Attributes
    ----------
    rule_id:
        The canonical rule identifier, e.g. ``"SC-TON-001"``.
    title:
        Short human-readable summary of the fix.
    before:
        Vulnerable / non-compliant code snippet.
    after:
        Remediated / compliant code snippet.
    explanation:
        Prose description of *why* the change is necessary and what it
        achieves.
    references:
        List of URLs or document identifiers for further reading.
    effort:
        Rough remediation effort bucket: ``"minutes"``, ``"hours"``, or
        ``"days"``.
    """

    rule_id: str
    title: str
    before: str
    after: str
    explanation: str
    references: List[str] = field(default_factory=list)
    effort: str = "minutes"

    def __post_init__(self) -> None:
        if self.effort not in {"minutes", "hours", "days"}:
            raise ValueError(
                f"effort must be 'minutes', 'hours', or 'days'; got {self.effort!r}"
            )


# ---------------------------------------------------------------------------
# Fix database
# ---------------------------------------------------------------------------

_FIX_DATABASE: Dict[str, FixSuggestion] = {

    # -----------------------------------------------------------------------
    # TON / FunC smart-contract rules
    # -----------------------------------------------------------------------

    "SC-TON-001": FixSuggestion(
        rule_id="SC-TON-001",
        title="Add sender address validation in FunC message handler",
        before="""\
;; VULNERABLE — any address can call this privileged function
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; ... privileged logic executed without checking caller ...
    int amount = in_msg_body~load_uint(64);
    send_raw_message(build_withdrawal_msg(amount), 64);
}
""",
        after="""\
;; SAFE — restrict to owner address stored in contract storage
global slice owner_address;

() load_data() impure {
    var ds = get_data().begin_parse();
    owner_address = ds~load_msg_addr();
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
    load_data();

    ;; Parse sender from the message envelope
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    if (flags & 1) { return (); }   ;; ignore bounced messages
    slice sender = cs~load_msg_addr();

    ;; Authorisation check
    throw_unless(401, equal_slices(sender, owner_address));

    int amount = in_msg_body~load_uint(64);
    send_raw_message(build_withdrawal_msg(amount), 64);
}
""",
        explanation=(
            "Without verifying the sender address, any actor on the network can "
            "invoke privileged entry points (e.g. fund withdrawals, configuration "
            "changes). Store the authorised owner address in persistent storage "
            "during deployment and compare it against the sender extracted from the "
            "fully-qualified inbound message cell. Use `throw_unless` so the "
            "transaction reverts cleanly on failure."
        ),
        references=[
            "https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1",
            "https://docs.ton.org/develop/func/cookbook#how-to-check-the-sender-address",
        ],
        effort="minutes",
    ),

    "SC-TON-002": FixSuggestion(
        rule_id="SC-TON-002",
        title="Replace weak randomness source in FunC with commit-reveal or VRF",
        before="""\
;; VULNERABLE — block logical time is miner-influenceable
() pick_winner() impure {
    int seed = now();           ;; predictable: unix timestamp
    int winner = seed % 100;
    pay_winner(winner);
}
""",
        after="""\
;; SAFE — two-phase commit-reveal randomness
;; Phase 1: participant submits hash(secret || nonce) on-chain
() commit(slice participant, int commitment) impure {
    ;; store commitment in hashmap keyed by participant address
    var (commits, _) = get_data().begin_parse().load_dict(256);
    commits~udict_set(256, slice_hash(participant), begin_cell()
        .store_uint(commitment, 256)
        .store_uint(now() + commit_window, 32)   ;; deadline
        .end_cell().begin_parse());
    set_data(begin_cell().store_dict(commits).end_cell());
}

;; Phase 2: participant reveals secret; contract verifies & derives randomness
() reveal(slice participant, int secret, int nonce) impure {
    var (commits, _) = get_data().begin_parse().load_dict(256);
    (slice entry, int found) = commits.udict_get?(256, slice_hash(participant));
    throw_unless(404, found);
    int stored_hash = entry~load_uint(256);
    throw_unless(400, stored_hash == cell_hash(
        begin_cell().store_uint(secret, 128).store_uint(nonce, 128).end_cell()));

    ;; Combine all revealed secrets with chain randomness for unpredictability
    randomize_lt();
    int random_value = rand(100);
    pick_winner_with(random_value);
}
""",
        explanation=(
            "On-chain values such as `now()`, `cur_lt()`, or block hashes are "
            "partially or fully controllable by validators/miners and must never "
            "be used as the sole entropy source for outcomes involving value. A "
            "commit-reveal scheme forces participants to lock in a secret before "
            "the reveal phase, preventing last-block manipulation. For higher "
            "security, integrate a verifiable random function (VRF) oracle."
        ),
        references=[
            "https://docs.ton.org/develop/smart-contracts/security/random",
            "https://blog.ton.org/secure-randomness-in-ton-smart-contracts",
        ],
        effort="hours",
    ),

    "SC-TON-003": FixSuggestion(
        rule_id="SC-TON-003",
        title="Bound loop iterations in FunC to prevent gas exhaustion / DoS",
        before="""\
;; VULNERABLE — iterates over caller-supplied length; no upper bound
() process_items(slice items_slice, int count) impure {
    int i = 0;
    while (i < count) {          ;; count comes from untrusted input
        int item = items_slice~load_uint(32);
        handle_item(item);
        i += 1;
    }
}
""",
        after="""\
;; SAFE — enforce a hard maximum and split large batches across messages
const int MAX_ITEMS_PER_TX = 255;   ;; tune to stay within gas limits

() process_items(slice items_slice, int count) impure {
    throw_unless(400, count > 0);
    throw_unless(429, count <= MAX_ITEMS_PER_TX);   ;; reject oversized batches

    int i = 0;
    while (i < count) {
        int item = items_slice~load_uint(32);
        handle_item(item);
        i += 1;
    }
}

;; For truly large datasets use pagination: store cursor in state and
;; process MAX_ITEMS_PER_TX items per incoming message.
""",
        explanation=(
            "TON charges gas per computation step. An unbounded loop driven by "
            "attacker-supplied input can exhaust the gas limit mid-execution, "
            "leaving the contract in an inconsistent state, or allow a malicious "
            "caller to craft transactions that always fail (DoS). Enforce an "
            "explicit upper bound on every loop whose trip count is derived from "
            "external data, and implement pagination for genuinely large data sets."
        ),
        references=[
            "https://docs.ton.org/develop/smart-contracts/guidelines/processing",
            "https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1#5-loop-gas-limit",
        ],
        effort="minutes",
    ),

    # -----------------------------------------------------------------------
    # Solidity / EVM smart-contract rules
    # -----------------------------------------------------------------------

    "SC-SOL-001": FixSuggestion(
        rule_id="SC-SOL-001",
        title="Fix reentrancy with checks-effects-interactions pattern",
        before="""\
// VULNERABLE — state updated AFTER external call
// solidity ^0.8.0
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call happens BEFORE state update — reentrancy window open
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] -= amount;   // too late
    }
}
""",
        after="""\
// SAFE — checks → effects → interactions
// solidity ^0.8.0
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external nonReentrant {
        // 1. Checks
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 2. Effects — update state BEFORE any external call
        balances[msg.sender] -= amount;

        // 3. Interactions
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
""",
        explanation=(
            "Reentrancy attacks exploit the window between an external call and "
            "the subsequent state update. The canonical mitigation is the "
            "checks-effects-interactions (CEI) pattern: validate inputs, update "
            "all internal state, then make external calls. Additionally, applying "
            "OpenZeppelin's `ReentrancyGuard.nonReentrant` modifier provides a "
            "second defensive layer at negligible gas cost."
        ),
        references=[
            "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
            "https://swcregistry.io/docs/SWC-107",
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
        ],
        effort="minutes",
    ),

    "SC-SOL-002": FixSuggestion(
        rule_id="SC-SOL-002",
        title="Eliminate integer overflow/underflow by upgrading to Solidity >=0.8 or using SafeMath",
        before="""\
// VULNERABLE — Solidity 0.7.x; arithmetic wraps silently
pragma solidity ^0.7.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // If balances[msg.sender] < amount this wraps to a huge number
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
""",
        after="""\
// SAFE — Solidity 0.8+ has built-in overflow checks at no extra gas (in most cases)
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // Reverts automatically on overflow / underflow
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// --- OR --- if you must stay on 0.7.x, use SafeMath:
// pragma solidity ^0.7.0;
// import "@openzeppelin/contracts/math/SafeMath.sol";
// contract Token {
//     using SafeMath for uint256;
//     mapping(address => uint256) public balances;
//     function transfer(address to, uint256 amount) external {
//         balances[msg.sender] = balances[msg.sender].sub(amount);
//         balances[to] = balances[to].add(amount);
//     }
// }
""",
        explanation=(
            "Prior to Solidity 0.8.0, unsigned integer arithmetic silently wraps "
            "on overflow and underflow. Upgrading the pragma to ^0.8.0 enables "
            "built-in checked arithmetic that reverts on overflow. For legacy "
            "codebases that cannot migrate, OpenZeppelin's SafeMath library "
            "provides equivalent protection. Auditors should verify `unchecked` "
            "blocks in 0.8+ code are intentional and safe."
        ),
        references=[
            "https://swcregistry.io/docs/SWC-101",
            "https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath",
            "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html",
        ],
        effort="hours",
    ),

    "SC-SOL-003": FixSuggestion(
        rule_id="SC-SOL-003",
        title="Replace tx.origin authentication with msg.sender",
        before="""\
// VULNERABLE — tx.origin can be spoofed via a phishing contract
pragma solidity ^0.8.0;

contract Wallet {
    address public owner;

    constructor() { owner = msg.sender; }

    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "Not owner");   // UNSAFE
        to.transfer(amount);
    }
}
""",
        after="""\
// SAFE — use msg.sender which always refers to the direct caller
pragma solidity ^0.8.0;

contract Wallet {
    address public owner;

    constructor() { owner = msg.sender; }

    function transfer(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");  // SAFE
        to.transfer(amount);
    }
}
""",
        explanation=(
            "`tx.origin` is the original externally-owned account that initiated "
            "the transaction chain. A malicious contract can trick an authorised "
            "user into calling it, which then forwards the call to the target "
            "contract; `tx.origin` still equals the victim's address. Always use "
            "`msg.sender` for authentication, which always reflects the immediate "
            "caller."
        ),
        references=[
            "https://swcregistry.io/docs/SWC-115",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/",
        ],
        effort="minutes",
    ),

    "SC-SOL-004": FixSuggestion(
        rule_id="SC-SOL-004",
        title="Check return value of low-level call() / send()",
        before="""\
// VULNERABLE — return value of call() silently ignored
pragma solidity ^0.8.0;

contract Distributor {
    function distribute(address[] calldata recipients, uint256 share) external payable {
        for (uint i = 0; i < recipients.length; i++) {
            recipients[i].call{value: share}("");  // failure not checked
        }
    }
}
""",
        after="""\
// SAFE — check success flag and revert or emit an event on failure
pragma solidity ^0.8.0;

contract Distributor {
    event TransferFailed(address indexed recipient, uint256 amount);

    function distribute(address[] calldata recipients, uint256 share) external payable {
        for (uint i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: share}("");
            if (!ok) {
                // Emit event rather than revert so other transfers succeed
                emit TransferFailed(recipients[i], share);
            }
        }
    }
}
""",
        explanation=(
            "The low-level `call()` function returns a boolean success flag; "
            "ignoring it means silent fund loss when a transfer fails. Always "
            "destructure the return tuple and handle the failure path. For "
            "single-recipient transfers, reverting is appropriate. For "
            "multi-recipient loops, consider emitting an event so legitimate "
            "transfers are not blocked by one failing recipient."
        ),
        references=[
            "https://swcregistry.io/docs/SWC-104",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
        ],
        effort="minutes",
    ),

    "SC-SOL-005": FixSuggestion(
        rule_id="SC-SOL-005",
        title="Remove or strictly gate selfdestruct usage",
        before="""\
// VULNERABLE — anyone can destroy the contract
pragma solidity ^0.8.0;

contract Killable {
    function kill() external {
        selfdestruct(payable(msg.sender));  // no access control
    }
}
""",
        after="""\
// SAFE option A — remove selfdestruct entirely (preferred for upgradeable contracts)
pragma solidity ^0.8.0;

contract SafeContract {
    // No selfdestruct — use a pause mechanism or proxy upgrade instead
}

// SAFE option B — restrict to owner with a time-lock
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";

contract ControlledKillable is Ownable {
    uint256 public killAfter;

    constructor(uint256 delaySeconds) {
        killAfter = block.timestamp + delaySeconds;
    }

    function kill() external onlyOwner {
        require(block.timestamp >= killAfter, "Time-lock active");
        selfdestruct(payable(owner()));
    }
}
""",
        explanation=(
            "`selfdestruct` permanently removes a contract and forwards its Ether "
            "balance; it cannot be undone. Without access control any caller can "
            "destroy the contract. The preferred fix is to remove `selfdestruct` "
            "entirely and use a pausable/upgradeable proxy pattern instead. If "
            "self-destruction is genuinely needed, gate it with `onlyOwner` and a "
            "time-lock to allow users to exit before destruction."
        ),
        references=[
            "https://swcregistry.io/docs/SWC-106",
            "https://eips.ethereum.org/EIPS/eip-6049",
        ],
        effort="hours",
    ),

    # -----------------------------------------------------------------------
    # Terraform / IaC rules
    # -----------------------------------------------------------------------

    "IAC-TF-001": FixSuggestion(
        rule_id="IAC-TF-001",
        title="Enable server-side encryption on S3 bucket",
        before="""\
# VULNERABLE — bucket has no default encryption rule
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}
""",
        after="""\
# SAFE — AES-256 SSE enforced at rest; deny unencrypted uploads via policy
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_kms_key" "s3_key" {
  description             = "S3 bucket encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# Deny PutObject calls that lack server-side encryption
resource "aws_s3_bucket_policy" "enforce_encryption" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnencryptedUploads"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.data.arn}/*"
      Condition = {
        StringNotEquals = {
          "s3:x-amz-server-side-encryption" = "aws:kms"
        }
      }
    }]
  })
}
""",
        explanation=(
            "Without server-side encryption, data stored in S3 is held in "
            "plaintext on AWS infrastructure. Adding a `server_side_encryption_"
            "configuration` block enables automatic encryption of every object "
            "using AWS KMS (or AES-256). Pairing this with a bucket policy that "
            "denies unencrypted `PutObject` requests ensures no application path "
            "can accidentally bypass the control."
        ),
        references=[
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
            "https://www.cisecurity.org/benchmark/amazon_web_services",
        ],
        effort="minutes",
    ),

    "IAC-TF-002": FixSuggestion(
        rule_id="IAC-TF-002",
        title="Restrict SSH (port 22) ingress to known CIDR blocks in Terraform security group",
        before="""\
# VULNERABLE — port 22 open to the entire internet
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # world-wide access
  }
}
""",
        after="""\
# SAFE — SSH restricted to a specific management CIDR or VPN gateway
variable "mgmt_cidr" {
  description = "CIDR block of management/VPN network allowed SSH access"
  type        = string
  # e.g. "10.0.0.0/8" for internal VPN range
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.mgmt_cidr]   # restricted to management network
    description = "SSH from management CIDR only"
  }

  # Prefer AWS Systems Manager Session Manager over SSH entirely:
  # https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
}
""",
        explanation=(
            "Exposing SSH to 0.0.0.0/0 makes every EC2 instance a brute-force "
            "target. Restrict port 22 ingress to your management network CIDR or, "
            "ideally, eliminate direct SSH access entirely by using AWS Systems "
            "Manager Session Manager, which provides audited shell access without "
            "opening any inbound port."
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html",
            "https://www.cisecurity.org/benchmark/amazon_web_services",
        ],
        effort="minutes",
    ),

    "IAC-TF-008": FixSuggestion(
        rule_id="IAC-TF-008",
        title="Move hardcoded secrets out of Terraform to environment variables or a secrets manager",
        before="""\
# VULNERABLE — database password hardcoded in plain text
resource "aws_db_instance" "main" {
  identifier        = "prod-db"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  username          = "admin"
  password          = "SuperSecret123!"   # NEVER do this
  skip_final_snapshot = true
}
""",
        after="""\
# SAFE option A — read secret from AWS Secrets Manager at plan time
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/db/master-password"
}

resource "aws_db_instance" "main" {
  identifier        = "prod-db"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  username          = "admin"
  password          = data.aws_secretsmanager_secret_version.db_password.secret_string
  skip_final_snapshot = false
}

# SAFE option B — pass via TF_VAR environment variable (never commit to VCS)
# export TF_VAR_db_password="$(aws secretsmanager get-secret-value ...)"
variable "db_password" {
  description = "Master DB password — supply via TF_VAR_db_password env var"
  type        = string
  sensitive   = true   # Terraform >= 0.14: redacts from plan output
}

resource "aws_db_instance" "main_v2" {
  identifier        = "prod-db"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  username          = "admin"
  password          = var.db_password
  skip_final_snapshot = false
}
""",
        explanation=(
            "Hardcoded secrets in Terraform files are committed to version control "
            "and stored in the Terraform state file, both of which are frequently "
            "exposed. Use AWS Secrets Manager (or HashiCorp Vault) data sources to "
            "pull secrets at plan/apply time, or supply them through the "
            "`TF_VAR_*` environment variable convention. Mark variables as "
            "`sensitive = true` so they are redacted from plan output. Rotate any "
            "secret that was previously committed."
        ),
        references=[
            "https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output",
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret_version",
            "https://www.vaultproject.io/docs/secrets",
        ],
        effort="hours",
    ),

    # -----------------------------------------------------------------------
    # CloudFormation rules
    # -----------------------------------------------------------------------

    "IAC-CF-001": FixSuggestion(
        rule_id="IAC-CF-001",
        title="Restrict SSH ingress in CloudFormation security group to a known CIDR",
        before="""\
# VULNERABLE — CloudFormation template allows SSH from anywhere
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Web server security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0   # open to the internet
""",
        after="""\
# SAFE — SSH locked to management CIDR supplied as a parameter
AWSTemplateFormatVersion: '2010-09-09'

Parameters:
  ManagementCIDR:
    Type: String
    Description: CIDR block permitted SSH access (e.g. VPN gateway)
    AllowedPattern: '(\d{1,3}\.){3}\d{1,3}/\d{1,2}'
    ConstraintDescription: Must be a valid CIDR block

Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Web server security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Ref ManagementCIDR   # restricted; never 0.0.0.0/0
""",
        explanation=(
            "Allowing SSH (port 22) from 0.0.0.0/0 exposes instances to "
            "internet-wide brute-force and credential-stuffing attacks. Parameterise "
            "the permitted CIDR block so it must be supplied explicitly at stack "
            "creation time, preventing accidental wildcard configuration. For "
            "production workloads, consider replacing SSH with AWS Systems Manager "
            "Session Manager and removing port 22 ingress entirely."
        ),
        references=[
            "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html",
        ],
        effort="minutes",
    ),

    # -----------------------------------------------------------------------
    # Kubernetes rules
    # -----------------------------------------------------------------------

    "IAC-K8S-005": FixSuggestion(
        rule_id="IAC-K8S-005",
        title="Remove privileged: true from Kubernetes container securityContext",
        before="""\
# VULNERABLE — container runs with full host privileges
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
        - name: web
          image: my-app:1.2.3
          securityContext:
            privileged: true          # grants all Linux capabilities
            runAsUser: 0              # root
""",
        after="""\
# SAFE — least-privilege securityContext with dropped capabilities
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: my-app:1.2.3
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 10001          # non-root UID
            runAsGroup: 10001
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE   # only add what is strictly required
""",
        explanation=(
            "A container with `privileged: true` has unrestricted access to the "
            "host kernel, devices, and namespaces — a full container escape becomes "
            "trivial. Remove the privileged flag, drop all Linux capabilities and "
            "re-add only those strictly required, run as a non-root UID, and enable "
            "`readOnlyRootFilesystem`. Apply a `seccompProfile` to restrict system "
            "calls. Use a Kubernetes `PodSecurityAdmission` policy to enforce these "
            "standards cluster-wide."
        ),
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
            "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        ],
        effort="minutes",
    ),

    # -----------------------------------------------------------------------
    # Container / Dockerfile rules
    # -----------------------------------------------------------------------

    "CONT-001": FixSuggestion(
        rule_id="CONT-001",
        title="Pin the base image to a specific immutable digest or versioned tag",
        before="""\
# VULNERABLE — mutable 'latest' tag; different image on every build
FROM python:latest

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
CMD ["python", "/app/main.py"]
""",
        after="""\
# SAFE — pin to a specific version tag AND verify with the SHA-256 digest
# Retrieve the digest: docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:f3614d9e6e3b7c2e5e4f2c6e8a1b3d7e9f2a4c6e8b1d3f5e7a9c2d4f6e8b1a3

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
CMD ["python", "/app/main.py"]
""",
        explanation=(
            "Using the `latest` tag (or any mutable tag) means the base image "
            "pulled during a build can change without notice, introducing unreviewed "
            "code, security patches, or regressions. Pin to an explicit semantic "
            "version tag and, for maximum reproducibility, append the `@sha256:…` "
            "digest. Automate digest updates with tools such as Renovate Bot or "
            "Dependabot."
        ),
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
            "https://snyk.io/blog/10-best-practices-to-containerize-nodejs-web-applications-with-docker/",
        ],
        effort="minutes",
    ),

    "CONT-002": FixSuggestion(
        rule_id="CONT-002",
        title="Run container processes as a non-root user",
        before="""\
# VULNERABLE — process runs as root (UID 0) by default
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
""",
        after="""\
# SAFE — create a dedicated non-root user and switch to it
FROM node:18-alpine

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY package*.json ./
RUN npm ci --production

COPY --chown=appuser:appgroup . .

# Drop to non-root for the runtime process
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]
""",
        explanation=(
            "Containers that run as root mean that any process-level vulnerability "
            "(RCE, path traversal, etc.) immediately gives an attacker root "
            "privileges inside the container and a much easier path to host escape. "
            "Create a dedicated, low-privilege OS user, `chown` application files to "
            "it, and switch with the `USER` directive before the entrypoint. "
            "Combine with `readOnlyRootFilesystem: true` in the Kubernetes pod spec "
            "for defence-in-depth."
        ),
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2-set-a-user",
        ],
        effort="minutes",
    ),

    "CONT-003": FixSuggestion(
        rule_id="CONT-003",
        title="Replace pipe-to-shell installer pattern with verified download",
        before="""\
# VULNERABLE — downloads and executes arbitrary code without verification
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://get.example.com/install.sh | bash
""",
        after="""\
# SAFE — download, verify checksum, then execute
FROM ubuntu:22.04

ARG TOOL_VERSION=1.2.3
ARG TOOL_SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://releases.example.com/v${TOOL_VERSION}/install.sh" \
         -o /tmp/install.sh \
    && echo "${TOOL_SHA256}  /tmp/install.sh" | sha256sum -c - \
    && chmod +x /tmp/install.sh \
    && /tmp/install.sh \
    && rm /tmp/install.sh

# Even better: install from the OS package manager or a signed package:
# RUN apt-get install -y example-tool=1.2.3
""",
        explanation=(
            "The pattern `curl … | bash` (or `wget … | sh`) executes remote code "
            "without any integrity check. A compromised CDN, DNS hijack, or "
            "man-in-the-middle attack can substitute a malicious payload. Download "
            "the script to disk first, verify its SHA-256 checksum against a known "
            "good value, then execute. Prefer OS package managers or verified "
            "binary releases with GPG signatures over shell installers."
        ),
        references=[
            "https://www.docker.com/blog/intro-guide-to-dockerfile-best-practices/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        ],
        effort="minutes",
    ),

    # -----------------------------------------------------------------------
    # Web3 / supply-chain rules
    # -----------------------------------------------------------------------

    "W3SC-001": FixSuggestion(
        rule_id="W3SC-001",
        title="Remove or replace a flagged malicious npm package",
        before="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "web3": "^1.9.0",
    "event-stream": "3.3.6",
    "flatmap-stream": "0.1.1"
  }
}
""",
        after="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "web3": "^1.9.0"
  }
}

// Steps to remediate:
// 1. Remove the malicious package:
//    npm uninstall event-stream flatmap-stream
//
// 2. Audit the entire dependency tree for known malicious packages:
//    npm audit
//    npx better-npm-audit audit --level critical
//
// 3. Check for injected code in node_modules before removal:
//    grep -r 'copay' node_modules/event-stream || true
//
// 4. Rotate any secrets (private keys, API keys) that may have been
//    exfiltrated while the package was installed.
//
// 5. Enable 'npm audit' in your CI pipeline and fail on critical severity.
""",
        explanation=(
            "Packages such as `event-stream@3.3.6` and `flatmap-stream@0.1.1` "
            "were found to contain deliberately injected malicious code targeting "
            "cryptocurrency wallet private keys. Remove any such package immediately, "
            "audit your full dependency tree, rotate all secrets that may have been "
            "accessible to the compromised package, and enable `npm audit` in CI to "
            "catch future introductions."
        ),
        references=[
            "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
            "https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities",
            "https://socket.dev/blog/inside-node-modules",
        ],
        effort="hours",
    ),

    "W3SC-002": FixSuggestion(
        rule_id="W3SC-002",
        title="Replace a typosquatting package with the legitimate dependency",
        before="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "ethres": "^5.7.0",
    "web-3": "^1.0.0",
    "hardhat-etherss": "^2.12.0"
  }
}
""",
        after="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "ethers": "^6.7.0",
    "web3": "^4.0.0",
    "hardhat-ethers": "^3.0.0"
  }
}

// Steps to remediate:
// 1. Uninstall typosquatted packages:
//    npm uninstall ethres web-3 hardhat-etherss
//
// 2. Install the legitimate packages:
//    npm install ethers web3 @nomicfoundation/hardhat-ethers
//
// 3. Verify package names against the official documentation before installing.
//
// 4. Use 'npm audit' and tools like Socket (socket.dev) or Snyk to scan
//    for typosquats in your dependency tree.
//
// 5. Rotate any private keys or secrets that may have been exposed.
""",
        explanation=(
            "Typosquatting packages mimic popular library names with minor "
            "misspellings (e.g., `ethres` vs `ethers`) and frequently contain "
            "credential-harvesting or cryptomining payloads. Uninstall the "
            "suspicious package, install the correctly-spelled legitimate package, "
            "and rotate any secrets that may have been accessed. Add automated "
            "typosquatting detection (e.g., Socket.dev GitHub App) to your CI "
            "pipeline."
        ),
        references=[
            "https://socket.dev/blog/npm-typosquatting-attacks",
            "https://snyk.io/blog/typosquatting-attacks/",
            "https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities",
        ],
        effort="minutes",
    ),

    "W3SC-003": FixSuggestion(
        rule_id="W3SC-003",
        title="Pin npm dependencies to exact versions and use a lockfile",
        before="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "ethers": "^6.7.0",
    "hardhat": ">=2.0.0",
    "@openzeppelin/contracts": "*"
  }
}
// package-lock.json is in .gitignore — NOT committed to repository
""",
        after="""\
{
  "name": "my-dapp",
  "version": "1.0.0",
  "dependencies": {
    "ethers": "6.7.1",
    "hardhat": "2.19.4",
    "@openzeppelin/contracts": "5.0.1"
  }
}
// package-lock.json MUST be committed to version control.
//
// Steps to remediate:
// 1. Pin every dependency to an exact version:
//    npm install --save-exact ethers@6.7.1 hardhat@2.19.4
//
// 2. Commit package-lock.json (or yarn.lock / pnpm-lock.yaml):
//    git add package.json package-lock.json
//
// 3. Remove 'package-lock.json' from .gitignore if present.
//
// 4. Use 'npm ci' (not 'npm install') in CI to install exactly what is in
//    the lockfile without resolution drift.
//
// 5. Automate version updates with Dependabot or Renovate Bot to receive
//    security patches in a controlled, reviewable manner.
""",
        explanation=(
            "Range specifiers such as `^`, `>=`, and `*` allow npm to resolve "
            "to newer patch or minor versions at install time. A compromised "
            "maintainer account can publish a malicious version that falls within "
            "your range and gets silently installed on the next `npm install`. "
            "Pin every production dependency to an exact version and commit the "
            "lockfile so every CI run uses an identical, reproducible dependency "
            "tree. Use `npm ci` in pipelines to enforce the lockfile."
        ),
        references=[
            "https://docs.npmjs.com/cli/v10/commands/npm-ci",
            "https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/",
            "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates",
        ],
        effort="minutes",
    ),
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class FixSuggestionsEngine:
    """
    Look up and enrich security findings with concrete remediation guidance.

    The engine wraps a static database of :class:`FixSuggestion` objects
    (one per rule ID) and exposes a small API used by the TythanAI pipeline
    to attach fix guidance to raw finding dicts produced by every scanner
    phase (phases 1-10).

    Usage
    -----
    >>> engine = FixSuggestionsEngine()
    >>> suggestion = engine.get("SC-SOL-001")
    >>> print(suggestion.title)
    Fix reentrancy with checks-effects-interactions pattern

    >>> findings = [{"rule_id": "SC-SOL-001", "severity": "CRITICAL"}]
    >>> enriched = engine.enrich(findings)
    >>> "fix_suggestion" in enriched[0]
    True

    >>> stats = engine.coverage()
    >>> print(stats["pct"])
    100.0
    """

    def __init__(self, database: Optional[Dict[str, FixSuggestion]] = None) -> None:
        """
        Initialise the engine.

        Parameters
        ----------
        database:
            Optional custom fix database mapping rule IDs to
            :class:`FixSuggestion` instances.  When *None* (the default)
            the built-in :data:`_FIX_DATABASE` is used.
        """
        self._db: Dict[str, FixSuggestion] = (
            database if database is not None else _FIX_DATABASE
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, rule_id: str) -> Optional[FixSuggestion]:
        """
        Return the :class:`FixSuggestion` for *rule_id*, or ``None``.

        Parameters
        ----------
        rule_id:
            The canonical rule identifier, e.g. ``"SC-TON-001"``.

        Returns
        -------
        FixSuggestion or None
            The suggestion record, or ``None`` if no entry exists for
            *rule_id*.

        Examples
        --------
        >>> engine = FixSuggestionsEngine()
        >>> fs = engine.get("IAC-TF-001")
        >>> fs.effort
        'minutes'
        >>> engine.get("NONEXISTENT") is None
        True
        """
        return self._db.get(rule_id)

    def enrich(self, findings: List[dict]) -> List[dict]:
        """
        Attach ``fix_suggestion`` data to each finding dict in *findings*.

        Each dict in *findings* must contain at minimum a ``"rule_id"``
        key.  If a :class:`FixSuggestion` exists for that rule ID, the
        serialised suggestion is added under the key ``"fix_suggestion"``.
        Findings whose rule ID has no corresponding entry are returned
        unchanged.

        Parameters
        ----------
        findings:
            List of finding dicts as produced by any TythanAI scanner
            phase.

        Returns
        -------
        List[dict]
            The same list with ``"fix_suggestion"`` injected where
            available.  The original dicts are mutated in-place and also
            returned for convenience.

        Raises
        ------
        KeyError
            If a finding dict does not contain a ``"rule_id"`` key.

        Examples
        --------
        >>> engine = FixSuggestionsEngine()
        >>> findings = [{"rule_id": "CONT-002", "file": "Dockerfile"}]
        >>> result = engine.enrich(findings)
        >>> result[0]["fix_suggestion"]["title"]
        'Run container processes as a non-root user'
        """
        for finding in findings:
            rule_id: str = finding["rule_id"]
            suggestion = self._db.get(rule_id)
            if suggestion is not None:
                finding["fix_suggestion"] = {
                    "rule_id": suggestion.rule_id,
                    "title": suggestion.title,
                    "before": suggestion.before,
                    "after": suggestion.after,
                    "explanation": suggestion.explanation,
                    "references": list(suggestion.references),
                    "effort": suggestion.effort,
                }
        return findings

    def get_all(self) -> Dict[str, FixSuggestion]:
        """
        Return a shallow copy of the entire fix database.

        Returns
        -------
        Dict[str, FixSuggestion]
            Mapping of rule ID → :class:`FixSuggestion` for every rule
            currently registered.

        Examples
        --------
        >>> engine = FixSuggestionsEngine()
        >>> all_fixes = engine.get_all()
        >>> "SC-TON-001" in all_fixes
        True
        """
        return dict(self._db)

    def coverage(self) -> dict:
        """
        Report how many known rules have fix suggestions.

        Because the database is fully populated for all registered rules,
        ``covered`` equals ``total_rules`` and ``pct`` is ``100.0`` for
        the default database.  When a custom database is injected (e.g.
        a subset of rules), these figures reflect that subset.

        Returns
        -------
        dict
            A dict with three keys:

            ``total_rules``  (int)
                Number of rule IDs in the database.
            ``covered``  (int)
                Number of rule IDs that have a non-empty
                :attr:`FixSuggestion.after` snippet (i.e. a concrete fix).
            ``pct``  (float)
                ``covered / total_rules * 100`` rounded to two decimal
                places, or ``0.0`` when the database is empty.

        Examples
        --------
        >>> engine = FixSuggestionsEngine()
        >>> cov = engine.coverage()
        >>> cov["covered"] == cov["total_rules"]
        True
        >>> cov["pct"]
        100.0
        """
        total = len(self._db)
        covered = sum(1 for fs in self._db.values() if fs.after.strip())
        pct = round(covered / total * 100, 2) if total > 0 else 0.0
        return {"total_rules": total, "covered": covered, "pct": pct}


# ---------------------------------------------------------------------------
# Module-level singleton for convenience
# ---------------------------------------------------------------------------

_default_engine: Optional[FixSuggestionsEngine] = None


def get_engine() -> FixSuggestionsEngine:
    """
    Return the module-level singleton :class:`FixSuggestionsEngine`.

    The instance is created on first call and reused thereafter.

    Returns
    -------
    FixSuggestionsEngine
    """
    global _default_engine
    if _default_engine is None:
        _default_engine = FixSuggestionsEngine()
    return _default_engine
