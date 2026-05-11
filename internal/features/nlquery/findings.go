package nlquery

import (
	"fmt"
)

type FindingQuery struct {
	SummarySQL string
	DetailSQL  string
}

func BuildFindingQueries(dataPath string) map[string]FindingQuery {
	// Use the parent CloudTrail directory to capture ALL accounts under the bucket
	// This enables cross-account correlation when multiple accounts are synced
	read := fmt.Sprintf(`read_json('%s**/*.json', maximum_object_size=16777216, auto_detect=true, union_by_name=true)`, dataPath)

	return map[string]FindingQuery{
		"root-account-usage": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.sourceIPAddress) as unique_ips FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'Root';`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.sourceIPAddress, r.eventTime, r.userAgent, r.awsRegion, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'Root' ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"cloudtrail-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'DeleteEventDataStore');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as identity, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'DeleteEventDataStore') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"unauthorized-api-calls": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as unique_identities FROM (SELECT unnest(Records) as r FROM %s) WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.errorCode, r.sourceIPAddress, COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') GROUP BY r.userIdentity.arn, r.eventName, r.errorCode, r.sourceIPAddress ORDER BY count DESC LIMIT 50;`, read),
		},
		"failed-console-logins": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.sourceIPAddress) as unique_ips FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName = 'ConsoleLogin' AND r.errorMessage IS NOT NULL;`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.sourceIPAddress, r.eventTime, r.errorMessage FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName = 'ConsoleLogin' AND r.errorMessage IS NOT NULL ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"iam-policy-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as actors FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'CreatePolicy', 'CreatePolicyVersion', 'DeletePolicy');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'CreatePolicy', 'CreatePolicyVersion', 'DeletePolicy') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"permission-boundary-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPermissionsBoundary', 'PutRolePermissionsBoundary', 'DeleteUserPermissionsBoundary', 'DeleteRolePermissionsBoundary');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('PutUserPermissionsBoundary', 'PutRolePermissionsBoundary', 'DeleteUserPermissionsBoundary', 'DeleteRolePermissionsBoundary') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"suspicious-cross-account": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.accountId) as foreign_accounts FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId;`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.accountId as source_account, r.recipientAccountId as target_account, r.userIdentity.arn as identity, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"security-group-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"role-assumption-patterns": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as unique_callers FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as caller, r.sourceIPAddress, r.eventTime, r.errorCode, COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity') GROUP BY r.userIdentity.arn, r.sourceIPAddress, r.eventTime, r.errorCode ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"access-key-creation": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateAccessKey', 'DeleteAccessKey');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateAccessKey', 'DeleteAccessKey') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"ec2-instance-sensitive-calls": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"lambda-sensitive-operations": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.invokedBy = 'lambda.amazonaws.com' AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.invokedBy = 'lambda.amazonaws.com' AND r.eventSource IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'kms.amazonaws.com', 'secretsmanager.amazonaws.com') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"uba-activity-by-hour": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE EXTRACT(HOUR FROM CAST(r.eventTime AS TIMESTAMP)) BETWEEN 0 AND 5 AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.sourceIPAddress, r.eventTime FROM (SELECT unnest(Records) as r FROM %s) WHERE EXTRACT(HOUR FROM CAST(r.eventTime AS TIMESTAMP)) BETWEEN 0 AND 5 AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"uba-high-error-rate": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT identity, total, errors, ROUND(errors * 100.0 / total, 1) as error_rate FROM (SELECT r.userIdentity.arn as identity, COUNT(*) as total, COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as errors FROM (SELECT unnest(Records) as r FROM %s) GROUP BY r.userIdentity.arn) WHERE total > 5 AND errors * 100.0 / total > 20);`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as identity, COUNT(*) as total, COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as errors, ROUND(COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as error_rate_pct FROM (SELECT unnest(Records) as r FROM %s) GROUP BY r.userIdentity.arn HAVING COUNT(*) > 5 AND COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) * 100.0 / COUNT(*) > 20 ORDER BY error_rate_pct DESC LIMIT 50;`, read),
		},
		"uba-human-user-write-ops": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count, COUNT(DISTINCT r.userIdentity.arn) as actors FROM (SELECT unnest(Records) as r FROM %s) WHERE r.readOnly = 'false' AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.readOnly = 'false' AND r.userIdentity."type" IN ('IAMUser', 'FederatedUser') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"vpc-changes": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateVpc', 'DeleteVpc', 'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'ModifyVpcAttribute', 'CreateSubnet', 'DeleteSubnet', 'CreateInternetGateway', 'AttachInternetGateway');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('CreateVpc', 'DeleteVpc', 'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'ModifyVpcAttribute', 'CreateSubnet', 'DeleteSubnet', 'CreateInternetGateway', 'AttachInternetGateway') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"resource-creation-deletion": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('RunInstances', 'TerminateInstances', 'CreateDBInstance', 'DeleteDBInstance', 'CreateFunction20150331', 'DeleteFunction20150331', 'CreateBucket', 'DeleteBucket');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.userIdentity.arn as actor, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.eventName IN ('RunInstances', 'TerminateInstances', 'CreateDBInstance', 'DeleteDBInstance', 'CreateFunction20150331', 'DeleteFunction20150331', 'CreateBucket', 'DeleteBucket') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
		"container-serverless-data-exfil": {
			SummarySQL: fmt.Sprintf(`SELECT COUNT(*) as count FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventName IN ('GetObject', 'PutObject', 'CopyObject', 'GetSecretValue', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'PutBucketPolicy', 'PutObjectAcl');`, read),
			DetailSQL: fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime, r.errorCode FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.eventName IN ('GetObject', 'PutObject', 'CopyObject', 'GetSecretValue', 'CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'PutBucketPolicy', 'PutObjectAcl') ORDER BY r.eventTime DESC LIMIT 50;`, read),
		},
	}
}
