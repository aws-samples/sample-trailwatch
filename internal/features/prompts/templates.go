package prompts

// PromptTemplate defines a pre-built prompt with placeholders.
type PromptTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt"`
	Parameters  []string `json:"parameters"`
}

// Categories for organizing templates.
var Categories = []string{
	"Access Key Discovery",
	"Malicious Activity",
	"Privilege Escalation",
	"Network Security",
	"Operational Changes",
	"User Behavior Analytics",
	"EC2 Instance Activity",
	"Container & Serverless",
}

// Templates is the full set of pre-built prompt templates.
var Templates = []PromptTemplate{
	// === Access Key Discovery ===
	{
		ID:          "failed-console-logins",
		Name:        "Failed Console Logins",
		Category:    "Access Key Discovery",
		Description: "Find failed AWS console login attempts with source IPs and error details",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all failed console login events (eventName='ConsoleLogin' where responseElements contains 'Failure') for account {account_id} in region {region} between {start_date} and {end_date}. Show the source IP, user identity, timestamp, and error message. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "access-key-creation",
		Name:        "Access Key Creation & Deletion",
		Category:    "Access Key Discovery",
		Description: "Track when IAM access keys were created or deleted",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all CreateAccessKey and DeleteAccessKey events for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, user who performed the action, target user (from requestParameters), timestamp, and source IP. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "access-key-last-used",
		Name:        "Access Key Usage Patterns",
		Category:    "Access Key Discovery",
		Description: "Find which access keys are being used and from where",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all API calls grouped by access key ID (userIdentity.accessKeyId) for account {account_id} in region {region} between {start_date} and {end_date}. For each access key, show: the key ID, associated user/role, number of API calls, distinct source IPs, first seen, and last seen timestamps. Sort by last seen descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === Malicious Activity ===
	{
		ID:          "unauthorized-api-calls",
		Name:        "Unauthorized API Calls",
		Category:    "Malicious Activity",
		Description: "Find API calls that returned AccessDenied or UnauthorizedOperation",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where errorCode is 'AccessDenied' or 'Client.UnauthorizedOperation' for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, user identity (ARN), source IP, error code, error message, and timestamp. Group by user and show count of denied calls. Sort by count descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "root-account-usage",
		Name:        "Root Account Usage",
		Category:    "Malicious Activity",
		Description: "Detect any usage of the AWS root account",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where userIdentity.type is 'Root' for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, source IP, user agent, timestamp, and whether MFA was used (from sessionContext). Sort by timestamp descending. Root account usage is a critical security finding.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "suspicious-cross-account",
		Name:        "Suspicious Cross-Account Activity",
		Category:    "Malicious Activity",
		Description: "Find API calls made by principals from other AWS accounts",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the userIdentity.accountId differs from {account_id} in region {region} between {start_date} and {end_date}. Show the source account ID, user ARN, event name, source IP, and timestamp. Group by source account and show the count of actions. This helps identify cross-account access patterns.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === Privilege Escalation ===
	{
		ID:          "iam-policy-changes",
		Name:        "IAM Policy Changes",
		Category:    "Privilege Escalation",
		Description: "Track changes to IAM policies, roles, and permissions",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all IAM policy modification events (PutUserPolicy, PutRolePolicy, PutGroupPolicy, AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, CreatePolicy, CreatePolicyVersion, DeletePolicy) for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, who made the change, what policy/role was affected (from requestParameters), timestamp, and source IP. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "role-assumption-patterns",
		Name:        "Role Assumption Patterns",
		Category:    "Privilege Escalation",
		Description: "Track AssumeRole calls to detect unusual role chaining",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all AssumeRole, AssumeRoleWithSAML, and AssumeRoleWithWebIdentity events for account {account_id} in region {region} between {start_date} and {end_date}. Show the caller identity, target role ARN (from requestParameters.roleArn), source IP, timestamp, and whether it succeeded or failed. Group by caller and target role to show assumption patterns.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "permission-boundary-changes",
		Name:        "Permission Boundary Modifications",
		Category:    "Privilege Escalation",
		Description: "Detect changes to permission boundaries which could enable escalation",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all PutUserPermissionsBoundary, PutRolePermissionsBoundary, DeleteUserPermissionsBoundary, and DeleteRolePermissionsBoundary events for account {account_id} in region {region} between {start_date} and {end_date}. Show who made the change, what entity was affected, the permission boundary ARN, timestamp, and source IP. Permission boundary removal is a high-severity finding.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === Network Security ===
	{
		ID:          "security-group-changes",
		Name:        "Security Group Modifications",
		Category:    "Network Security",
		Description: "Track changes to security group rules (ingress/egress)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all AuthorizeSecurityGroupIngress, AuthorizeSecurityGroupEgress, RevokeSecurityGroupIngress, RevokeSecurityGroupEgress, CreateSecurityGroup, and DeleteSecurityGroup events for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, who made the change, security group ID, the rule details (from requestParameters including IP ranges and ports), timestamp, and source IP. Flag any rules that open 0.0.0.0/0.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "vpc-changes",
		Name:        "VPC Infrastructure Changes",
		Category:    "Network Security",
		Description: "Track VPC creation, deletion, and peering changes",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all VPC-related events (CreateVpc, DeleteVpc, CreateVpcPeeringConnection, AcceptVpcPeeringConnection, ModifyVpcAttribute, CreateSubnet, DeleteSubnet, CreateInternetGateway, AttachInternetGateway) for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, who made the change, VPC/subnet IDs affected, timestamp, and source IP. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "nacl-changes",
		Name:        "Network ACL Updates",
		Category:    "Network Security",
		Description: "Track changes to Network ACLs",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all CreateNetworkAclEntry, DeleteNetworkAclEntry, ReplaceNetworkAclEntry, and ReplaceNetworkAclAssociation events for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, who made the change, NACL ID, rule details (from requestParameters), timestamp, and source IP. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === Operational Changes ===
	{
		ID:          "resource-creation-deletion",
		Name:        "Resource Creation & Deletion",
		Category:    "Operational Changes",
		Description: "Track EC2, RDS, Lambda, and S3 resource lifecycle events",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all major resource lifecycle events (RunInstances, TerminateInstances, CreateDBInstance, DeleteDBInstance, CreateFunction20150331, DeleteFunction20150331, CreateBucket, DeleteBucket) for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, event source (service), who performed it, resource identifiers from requestParameters, timestamp, and source IP. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "config-changes",
		Name:        "Configuration Changes",
		Category:    "Operational Changes",
		Description: "Track modifications to service configurations",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where eventName starts with 'Modify', 'Update', or 'Put' (configuration changes) for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, event source, who made the change, timestamp, and source IP. Group by event source and event name to show which services had the most configuration changes.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "cloudtrail-changes",
		Name:        "CloudTrail Configuration Changes",
		Category:    "Operational Changes",
		Description: "Detect tampering with CloudTrail logging itself",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all CloudTrail-related events (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, DeleteEventDataStore) for account {account_id} in region {region} between {start_date} and {end_date}. Show the event name, who performed it, trail/resource affected, timestamp, and source IP. Any StopLogging or DeleteTrail event is a critical security finding that may indicate an attacker covering their tracks.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === User Behavior Analytics ===

	// --- AWS Service Activity ---
	{
		ID:          "uba-service-role-activity",
		Name:        "AWS Service Role Activity Summary",
		Category:    "User Behavior Analytics",
		Description: "All activity performed by AWS services (Config, CloudFormation, Lambda execution roles, etc.)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where userIdentity.\"type\" = 'AWSService' OR userIdentity.invokedBy IS NOT NULL for account {account_id} in region {region} between {start_date} and {end_date}. Group by the invoking service (userIdentity.invokedBy) and eventName. For each service, show: service name, top 10 API calls made, total call count, distinct event sources targeted, and time range of activity. Sort by total call count descending. This shows the baseline of automated AWS service activity in the account.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "uba-service-role-unusual",
		Name:        "Unusual Service Role Behavior",
		Category:    "User Behavior Analytics",
		Description: "Service roles making unexpected API calls (write operations, IAM changes)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where userIdentity.\"type\" = 'AWSService' OR userIdentity.invokedBy IS NOT NULL, AND the event is a write operation (readOnly = 'false') that targets IAM, STS, KMS, or CloudTrail services (eventSource in 'iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'cloudtrail.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Show the invoking service, event name, event source, any error codes, and timestamp. These are potentially suspicious — services normally don't modify IAM or security configurations.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// --- Human User Activity ---
	{
		ID:          "uba-human-user-timeline",
		Name:        "Human User Activity Timeline",
		Category:    "User Behavior Analytics",
		Description: "All activity by human users (IAM users, federated, console sessions)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where userIdentity.\"type\" IN ('IAMUser', 'FederatedUser') OR (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.sessionContext.sessionIssuer.userName IS NOT NULL AND userIdentity.invokedBy IS NULL) for account {account_id} in region {region} between {start_date} and {end_date}. Group by user identity (ARN or userName). For each user show: user name/ARN, total API calls, distinct event names, distinct source IPs, first activity timestamp, last activity timestamp, and whether any calls had errors. Sort by total API calls descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "uba-human-user-write-ops",
		Name:        "Human User Write Operations",
		Category:    "User Behavior Analytics",
		Description: "All mutating (write) actions performed by human users — changes to infrastructure",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where readOnly = 'false' AND the caller is a human user (userIdentity.\"type\" IN ('IAMUser', 'FederatedUser') OR (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL)) for account {account_id} in region {region} between {start_date} and {end_date}. Show the user identity (ARN), event name, event source, source IP, timestamp, and whether it succeeded or failed (errorCode). Sort by timestamp descending. This is the audit trail of all human-initiated changes.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// --- Machine/Instance Activity ---
	{
		ID:          "uba-machine-identity-activity",
		Name:        "EC2/Machine Identity Activity",
		Category:    "User Behavior Analytics",
		Description: "All activity from EC2 instances, Lambda, ECS tasks using instance roles (IMDS credentials)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where userIdentity.\"type\" = 'AssumedRole' AND userIdentity.sessionContext.sessionIssuer.\"type\" = 'Role' AND (userIdentity.sessionContext.ec2RoleDelivery IS NOT NULL OR userIdentity.arn LIKE '%:assumed-role/%') AND userIdentity.invokedBy IS NULL for account {account_id} in region {region} between {start_date} and {end_date}. Group by the role name (sessionContext.sessionIssuer.userName). For each role show: role name, total API calls, distinct event names (top 10), distinct source IPs, and time range. Sort by total calls descending. This shows what your compute workloads (EC2, Lambda, ECS) are doing.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "uba-machine-unusual-calls",
		Name:        "Machine Roles Making Unusual Calls",
		Category:    "User Behavior Analytics",
		Description: "Instance/Lambda roles calling sensitive APIs they normally shouldn't (IAM, STS, data exfil)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is a machine identity (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL AND userIdentity.sessionContext.sessionIssuer.\"type\" = 'Role') AND the event targets sensitive services or actions: eventName IN ('CreateAccessKey', 'CreateUser', 'CreateRole', 'PutRolePolicy', 'AttachRolePolicy', 'GetSecretValue', 'Decrypt', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'GetObject') for account {account_id} in region {region} between {start_date} and {end_date}. Show the role name, event name, event source, source IP, timestamp, and error code. These could indicate a compromised instance attempting privilege escalation or data exfiltration.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// --- Temporal Patterns ---
	{
		ID:          "uba-activity-by-hour",
		Name:        "Activity by Hour (Anomaly Detection)",
		Category:    "User Behavior Analytics",
		Description: "API call distribution by hour — flag off-hours activity",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to analyze activity patterns by hour of day for account {account_id} in region {region} between {start_date} and {end_date}. For each hour (0-23 UTC), show: total API calls, count of distinct human users active, count of write operations, and count of error events. Also separately list any human user activity (userIdentity.\"type\" IN ('IAMUser', 'FederatedUser', 'AssumedRole') AND userIdentity.invokedBy IS NULL) occurring between 00:00-06:00 UTC with full details (user, event, IP, time). Off-hours human activity is a strong indicator of compromise or insider threat.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// --- Source IP Patterns ---
	{
		ID:          "uba-internal-ip-activity",
		Name:        "Internal IP Activity (VPC/Private)",
		Category:    "User Behavior Analytics",
		Description: "All API calls originating from internal/private IP addresses (10.x, 172.16-31.x, 192.168.x) or AWS service IPs",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where sourceIPAddress matches internal/private ranges (starts with '10.', '172.16.' through '172.31.', '192.168.') OR sourceIPAddress ends with '.amazonaws.com' (AWS service calls) for account {account_id} in region {region} between {start_date} and {end_date}. Group by sourceIPAddress and userIdentity ARN. For each source, show: IP address, user/role identity, total API calls, distinct event names, and whether it's a private IP or AWS service. Sort by total calls descending. Internal IPs indicate activity from within your VPC (EC2 instances, Lambda in VPC, etc.).",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "uba-external-ip-activity",
		Name:        "External IP Activity (Public Internet)",
		Category:    "User Behavior Analytics",
		Description: "All API calls from public/external IPs — console users, CLI from laptops, potential attackers",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where sourceIPAddress does NOT start with '10.', '172.16.' through '172.31.', '192.168.' AND does NOT end with '.amazonaws.com' for account {account_id} in region {region} between {start_date} and {end_date}. Group by sourceIPAddress. For each external IP show: the IP, all user identities that used it, total API calls, distinct event names, any error codes, first seen and last seen timestamps. Sort by total calls descending. Flag any IP that is associated with multiple different user identities (potential credential sharing or theft).",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "uba-ip-per-identity",
		Name:        "Unique Source IPs per Identity",
		Category:    "User Behavior Analytics",
		Description: "How many different IPs each user/role uses — flag identities with many IPs (possible compromise)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all distinct sourceIPAddress values per user identity (userIdentity.arn) for account {account_id} in region {region} between {start_date} and {end_date}. For each identity show: ARN, identity type, count of distinct source IPs, list of all IPs used (comma-separated), total API calls, and whether any IPs are external (not 10.x, 172.16-31.x, 192.168.x, or *.amazonaws.com). Sort by distinct IP count descending. Identities using many different external IPs may indicate compromised credentials being used from multiple locations.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// --- Error Rate / Probing ---
	{
		ID:          "uba-high-error-rate",
		Name:        "High Error Rate Users (Probing Detection)",
		Category:    "User Behavior Analytics",
		Description: "Identities with high failure rates — potential enumeration or permission probing",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to calculate the error rate per user identity for account {account_id} in region {region} between {start_date} and {end_date}. For each identity (userIdentity.arn), compute: total API calls, calls with errorCode IS NOT NULL, error rate percentage, distinct error codes seen, distinct event names attempted, and source IPs. Only show identities with error rate > 20%% OR more than 10 failed calls. Sort by error count descending. High error rates suggest permission probing, enumeration attacks, or misconfigured automation.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === EC2 Instance Activity ===
	{
		ID:          "ec2-instance-role-activity",
		Name:        "EC2 Instance Role Activity (IMDS)",
		Category:    "EC2 Instance Activity",
		Description: "All API calls made by EC2 instances using instance profile credentials (IMDS v1/v2)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is an EC2 instance using instance profile credentials. Identify these by: userIdentity.\"type\" = 'AssumedRole' AND userIdentity.sessionContext.sessionIssuer.\"type\" = 'Role' AND (userIdentity.sessionContext.ec2RoleDelivery IS NOT NULL OR userIdentity.arn LIKE '%%:assumed-role/%%') AND userIdentity.invokedBy IS NULL AND sourceIPAddress NOT LIKE '%%.amazonaws.com' for account {account_id} in region {region} between {start_date} and {end_date}. Group by the role name (sessionContext.sessionIssuer.userName) and sourceIPAddress (which is the instance's private IP). For each instance/role combination show: role name, source IP (instance IP), total API calls, top 10 event names, distinct event sources, first and last activity time. Sort by total calls descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ec2-instance-sensitive-calls",
		Name:        "EC2 Instances Making Sensitive API Calls",
		Category:    "EC2 Instance Activity",
		Description: "EC2 instances calling IAM, STS, KMS, Secrets Manager — potential compromise indicators",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is an EC2 instance (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL AND sourceIPAddress NOT LIKE '%%.amazonaws.com') AND the event targets sensitive services: eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com', 'ssm.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Show the role name, source IP (instance), event name, event source, error code (if any), and timestamp. Sort by timestamp descending. EC2 instances calling IAM or STS APIs beyond AssumeRole may indicate credential theft or lateral movement.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ec2-instance-data-access",
		Name:        "EC2 Instance Data Access Patterns",
		Category:    "EC2 Instance Activity",
		Description: "S3, DynamoDB, RDS data access from EC2 instances — detect data exfiltration",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all data-plane events from EC2 instances (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL AND sourceIPAddress NOT LIKE '%%.amazonaws.com') targeting data services: eventSource IN ('s3.amazonaws.com', 'dynamodb.amazonaws.com', 'rds.amazonaws.com', 'rds-data.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name and source IP. For each show: instance role, IP, event names (GetObject, PutObject, Query, etc.), count per event, and any errors. Flag instances with high GetObject/PutObject counts or accessing unusual buckets. Sort by total data calls descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ec2-instance-network-changes",
		Name:        "EC2 Instances Modifying Network Config",
		Category:    "EC2 Instance Activity",
		Description: "EC2 instances changing security groups, routes, or network ACLs — lateral movement indicator",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all network modification events originating from EC2 instances (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL AND sourceIPAddress NOT LIKE '%%.amazonaws.com') where eventName matches network changes: AuthorizeSecurityGroupIngress, AuthorizeSecurityGroupEgress, CreateRoute, ReplaceRoute, ModifyInstanceAttribute, AssociateAddress, AllocateAddress for account {account_id} in region {region} between {start_date} and {end_date}. Show the role name, source IP, event name, request parameters (security group, route details), timestamp, and error code. Any EC2 instance modifying network rules is highly suspicious and may indicate compromise.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ec2-static-key-activity",
		Name:        "EC2 Instances Using Static Access Keys",
		Category:    "EC2 Instance Activity",
		Description: "API calls from private IPs using long-lived access keys (not instance roles) — bad practice or compromise",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where sourceIPAddress starts with '10.' or '172.16.' through '172.31.' or '192.168.' (internal IPs indicating EC2/VPC origin) AND userIdentity.\"type\" = 'IAMUser' (using static access keys, not instance roles) for account {account_id} in region {region} between {start_date} and {end_date}. Group by userIdentity.userName and sourceIPAddress. For each show: IAM user name, access key ID, source IP, total API calls, distinct event names, and time range. Static keys on EC2 instances are a security anti-pattern — instances should use IAM roles via IMDS instead.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ec2-cross-instance-patterns",
		Name:        "Cross-Instance Activity Patterns",
		Category:    "EC2 Instance Activity",
		Description: "Same role used from multiple IPs — detect lateral movement across instances",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all instance roles (userIdentity.\"type\" = 'AssumedRole' AND userIdentity.invokedBy IS NULL AND sourceIPAddress NOT LIKE '%%.amazonaws.com') that are active from multiple distinct source IPs for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name (sessionContext.sessionIssuer.userName). For each role show: role name, count of distinct source IPs, list all IPs, total API calls, and whether any IPs appeared only briefly (single event). Roles appearing from many IPs could indicate: multiple instances sharing a role (normal) or credential theft and reuse from another location (suspicious if IPs are external).",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},

	// === Container & Serverless ===
	{
		ID:          "lambda-execution-activity",
		Name:        "Lambda Function Execution Activity",
		Category:    "Container & Serverless",
		Description: "All API calls made by Lambda execution roles — what your functions are doing",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is a Lambda function. Identify Lambda by: userIdentity.\"type\" = 'AssumedRole' AND (userIdentity.arn LIKE '%%:assumed-role/%%' AND (userIdentity.sessionContext.sessionIssuer.userName LIKE '%%lambda%%' OR userIdentity.sessionContext.sessionIssuer.userName LIKE '%%Lambda%%' OR userIdentity.invokedBy = 'lambda.amazonaws.com')) for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name. For each Lambda role show: role name, total API calls, top event names, distinct event sources targeted, error count, and time range. Sort by total calls descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "lambda-sensitive-operations",
		Name:        "Lambda Functions Calling Sensitive APIs",
		Category:    "Container & Serverless",
		Description: "Lambda functions accessing IAM, KMS, Secrets Manager, or making cross-account calls",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is a Lambda function (userIdentity.arn LIKE '%%:assumed-role/%%' AND (userIdentity.sessionContext.sessionIssuer.userName LIKE '%%lambda%%' OR userIdentity.invokedBy = 'lambda.amazonaws.com')) AND eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com', 'lambda.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Show the Lambda role, event name, event source, error code, and timestamp. Flag any CreateAccessKey, PutRolePolicy, or InvokeFunction calls as high-risk. Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "ecs-task-activity",
		Name:        "ECS Task Activity",
		Category:    "Container & Serverless",
		Description: "All API calls from ECS tasks using task roles",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is an ECS task. Identify ECS tasks by: userIdentity.\"type\" = 'AssumedRole' AND (userIdentity.arn LIKE '%%:assumed-role/ecsTaskRole%%' OR userIdentity.arn LIKE '%%:assumed-role/ecs%%' OR userIdentity.invokedBy = 'ecs-tasks.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name and source IP. For each ECS task role show: role name, source IPs (task IPs), total API calls, top event names, distinct services called, error count, and time range. Sort by total calls descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "eks-pod-activity",
		Name:        "EKS Pod Activity (IRSA)",
		Category:    "Container & Serverless",
		Description: "API calls from EKS pods using IAM Roles for Service Accounts (IRSA)",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is an EKS pod using IRSA. Identify IRSA by: userIdentity.\"type\" = 'AssumedRole' AND userIdentity.sessionContext.webIdFederationData IS NOT NULL AND userIdentity.sessionContext.webIdFederationData.federatedProvider LIKE '%%oidc.eks%%' for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name. For each IRSA role show: role name, OIDC provider, total API calls, top event names, distinct services called, source IPs, error count, and time range. If IRSA data is not available, fall back to finding roles with 'eks' in the name: userIdentity.sessionContext.sessionIssuer.userName LIKE '%%eks%%'.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "container-serverless-errors",
		Name:        "Container/Serverless Permission Errors",
		Category:    "Container & Serverless",
		Description: "AccessDenied errors from Lambda, ECS, EKS — misconfigured roles or privilege escalation attempts",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events with errorCode = 'AccessDenied' or errorCode = 'Client.UnauthorizedOperation' where the caller is a compute workload (Lambda, ECS, or EKS — identified by role names containing 'lambda', 'ecs', 'eks', or invokedBy in 'lambda.amazonaws.com', 'ecs-tasks.amazonaws.com') for account {account_id} in region {region} between {start_date} and {end_date}. Group by role name and event name. For each show: role name, event name attempted, event source, error code, count of failures, and sample timestamps. High failure counts from compute roles may indicate: misconfigured IAM policies (common), compromised workloads probing for permissions (critical), or deployment issues.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
	{
		ID:          "container-serverless-data-exfil",
		Name:        "Container/Serverless Data Exfiltration Signals",
		Category:    "Container & Serverless",
		Description: "Lambda/ECS/EKS workloads accessing S3, Secrets, or making unusual external calls",
		Prompt:      "Using DuckDB, query the CloudTrail JSON logs at {data_path} to find all events where the caller is a compute workload (Lambda, ECS, EKS — roles containing 'lambda', 'ecs', 'eks' or invokedBy matching these services) AND the event involves data access or exfiltration patterns: eventName IN ('GetObject', 'PutObject', 'CopyObject', 'GetSecretValue', 'Decrypt', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'PutBucketPolicy', 'PutObjectAcl') for account {account_id} in region {region} between {start_date} and {end_date}. Show the role name, event name, event source, request parameters (bucket/key/secret name where available), timestamp, and error code. Flag any PutBucketPolicy, ModifySnapshotAttribute, or PutObjectAcl as high-risk (making data public). Sort by timestamp descending.",
		Parameters:  []string{"account_id", "region", "start_date", "end_date", "data_path"},
	},
}
