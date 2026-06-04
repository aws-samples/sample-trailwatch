package nlquery

import (
	"fmt"
)

type FindingQuery struct {
	SummarySQL string
	DetailSQL  string
}

// Off-hours window for the "human activity at unusual times" compromise
// indicator (uba-activity-by-hour). These bounds are in UTC because CloudTrail
// eventTime is recorded in UTC and we compare against it directly without a
// timezone conversion. For an org whose operators work in a single non-UTC
// timezone this UTC window produces systematic false positives (e.g. a US-East
// workday overlaps this UTC range). We document the assumption rather than
// infer the org's timezone — an operator can adjust these constants to their
// own off-hours window (e.g. for US-Pacific business hours, roughly 02:00-13:00
// UTC would be "on-hours", so off-hours would be the complement). The bounds
// are inclusive and the SQL uses BETWEEN, so this covers 00:00:00 through
// 06:59:59 UTC.
const (
	offHoursStartUTC = 0 // inclusive: 00:00 UTC
	offHoursEndUTC   = 6 // inclusive: through 06:59 UTC
)

func BuildFindingQueries(dataPath string) map[string]FindingQuery {
	// Use the parent CloudTrail directory to capture ALL accounts under the bucket
	// This enables cross-account correlation when multiple accounts are synced.
	// dataPath is config-derived, so escape any single quotes before interpolating
	// it into the read_json('...') literal — an unescaped quote would break out of
	// the literal and could bypass the read-only SQL allowlist (see safesql.go).
	read := fmt.Sprintf(`read_json('%s**/*.json', maximum_object_size=%d, auto_detect=true, union_by_name=true)`, escapeSQLLiteral(dataPath), maxObjectSize)

	return map[string]FindingQuery{
		"root-account-usage": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.sourceIPAddress) as unique_ips FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'Root';`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.sourceIPAddress, r.eventTime, r.userAgent, r.awsRegion, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'Root' ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"cloudtrail-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'DeleteEventDataStore');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as identity, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'DeleteEventDataStore') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"unauthorized-api-calls": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as unique_identities FROM (SELECT unnest(Records) as r FROM %s) WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.errorCode, r.sourceIPAddress, COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') GROUP BY r.userIdentity.arn, r.eventName, r.errorCode, r.sourceIPAddress ORDER BY count DESC LIMIT 50;`, read),
		},
		"failed-console-logins": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.sourceIPAddress) as unique_ips FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName = 'ConsoleLogin' AND r.errorMessage IS NOT NULL;`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.sourceIPAddress, r.eventTime, r.errorMessage FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName = 'ConsoleLogin' AND r.errorMessage IS NOT NULL ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"iam-policy-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as actors FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'CreatePolicy', 'CreatePolicyVersion', 'DeletePolicy');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'CreatePolicy', 'CreatePolicyVersion', 'DeletePolicy') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"permission-boundary-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPermissionsBoundary', 'PutRolePermissionsBoundary', 'DeleteUserPermissionsBoundary', 'DeleteRolePermissionsBoundary');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPermissionsBoundary', 'PutRolePermissionsBoundary', 'DeleteUserPermissionsBoundary', 'DeleteRolePermissionsBoundary') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"suspicious-cross-account": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.accountId) as foreign_accounts FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId;`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.accountId as source_account, r.recipientAccountId as target_account, r.userIdentity.arn as identity, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"security-group-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"role-assumption-patterns": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as unique_callers FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as caller, r.sourceIPAddress, r.eventTime, r.errorCode, COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity') GROUP BY r.userIdentity.arn, r.sourceIPAddress, r.eventTime, r.errorCode ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"access-key-creation": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateAccessKey', 'DeleteAccessKey');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateAccessKey', 'DeleteAccessKey') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"ec2-instance-sensitive-calls": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"lambda-sensitive-operations": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.invokedBy = 'lambda.amazonaws.com' AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.invokedBy = 'lambda.amazonaws.com' AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"uba-activity-by-hour": {
			// Human off-hours activity. eventTime is UTC; the window is the UTC
			// constants documented at offHoursStartUTC/offHoursEndUTC. Identity
			// types cover human-driven activity: IAMUser, FederatedUser, and
			// AssumedRole (federated SSO / role-chained human sessions show up as
			// AssumedRole and were previously omitted). The BETWEEN bounds match
			// the constants so code and comment agree.
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE EXTRACT(HOUR FROM CAST(r.eventTime AS TIMESTAMP)) BETWEEN %d AND %d AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser', 'AssumedRole');`, read, offHoursStartUTC, offHoursEndUTC),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.sourceIPAddress, r.eventTime FROM (SELECT unnest(Records) as r FROM %s) WHERE EXTRACT(HOUR FROM CAST(r.eventTime AS TIMESTAMP)) BETWEEN %d AND %d AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser', 'AssumedRole') ORDER BY r.eventTime DESC LIMIT 50;`, read, offHoursStartUTC, offHoursEndUTC),
		},
		"uba-high-error-rate": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT identity, total, errors, ROUND(errors * 100.0 / total, 1) as error_rate FROM (SELECT r.userIdentity.arn as identity, COUNT(*) as total, COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as errors FROM (SELECT unnest(Records) as r FROM %s) GROUP BY r.userIdentity.arn) WHERE total > 5 AND errors * 100.0 / total > 20);`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as identity, COUNT(*) as total, COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as errors, ROUND(COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as error_rate_pct FROM (SELECT unnest(Records) as r FROM %s) GROUP BY r.userIdentity.arn HAVING COUNT(*) > 5 AND COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) * 100.0 / COUNT(*) > 20 ORDER BY error_rate_pct DESC LIMIT 50;`, read),
		},
		"uba-human-user-write-ops": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as actors FROM (SELECT unnest(Records) as r FROM %s) WHERE r.readOnly = 'false' AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.readOnly = 'false' AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"vpc-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateVpc', 'DeleteVpc', 'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'ModifyVpcAttribute', 'CreateSubnet', 'DeleteSubnet', 'CreateInternetGateway', 'AttachInternetGateway');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateVpc', 'DeleteVpc', 'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'ModifyVpcAttribute', 'CreateSubnet', 'DeleteSubnet', 'CreateInternetGateway', 'AttachInternetGateway') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"resource-creation-deletion": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('RunInstances', 'TerminateInstances', 'CreateDBInstance', 'DeleteDBInstance', 'CreateFunction20150331', 'DeleteFunction20150331', 'CreateBucket', 'DeleteBucket');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('RunInstances', 'TerminateInstances', 'CreateDBInstance', 'DeleteDBInstance', 'CreateFunction20150331', 'DeleteFunction20150331', 'CreateBucket', 'DeleteBucket') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"container-serverless-data-exfil": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventName IN ('GetObject', 'PutObject', 'CopyObject', 'GetSecretValue', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'PutBucketPolicy', 'PutObjectAcl');`, read),
			DetailSQL:  fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventName IN ('GetObject', 'PutObject', 'CopyObject', 'GetSecretValue', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'PutBucketPolicy', 'PutObjectAcl') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
	}
}
