// Package awsutil contains shared AWS SDK configuration helpers.
package awsutil

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// NewIMDSv2Provider returns an EC2 role provider that fails closed when an
// IMDSv2 token cannot be obtained instead of falling back to IMDSv1.
func NewIMDSv2Provider() *ec2rolecreds.Provider {
	client := imds.New(imds.Options{EnableFallback: aws.FalseTernary})
	return ec2rolecreds.New(func(options *ec2rolecreds.Options) {
		options.Client = client
	})
}
