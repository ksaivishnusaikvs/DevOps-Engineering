from cdktf import App, TerraformStack
from constructs import Construct

from cdktf_cdktf_provider_aws.provider import AwsProvider
from cdktf_cdktf_provider_aws.s3_bucket import S3Bucket
from cdktf_cdktf_provider_aws.s3_bucket_versioning import S3BucketVersioningA
from cdktf_cdktf_provider_aws.s3_bucket_public_access_block import (
	S3BucketPublicAccessBlock
)
from cdktf_cdktf_provider_aws.s3_bucket_server_side_encryption_configuration import (
    S3BucketServerSideEncryptionConfigurationA
)


class ProdS3Stack(TerraformStack):

	def __init__(self, scope: Construct, stack_id: str):
    	super().__init__(scope, stack_id)

    	# AWS provider
    	AwsProvider(
        	self,
        	"aws",
        	region="ap-south-1"
    	)

    	# S3 bucket
    	bucket = S3Bucket(
        	self,
        	"prod-bucket",
            bucket="kv-prod-s3-demo-20260909",
        	tags={
            	"Environment": "prod",
            	"Application": "my-app",
            	"ManagedBy": "cdktf"
        	}
    	)

    	# Versioning
    	S3BucketVersioningA(
        	self,
        	"versioning",
        	bucket=bucket.id,
        	versioning_configuration={
            	"status": "Enabled"
        	}
    	)

    	# Block public access
    	S3BucketPublicAccessBlock(
        	self,
        	"public-access",
        	bucket=bucket.id,
        	block_public_acls=True,
        	block_public_policy=True,
        	ignore_public_acls=True,
        	restrict_public_buckets=True
    	)

    	# Server-side encryption
        S3BucketServerSideEncryptionConfigurationA(
        	self,
        	"encryption",
        	bucket=bucket.id,
        	rule=[
            	{
                    "apply_server_side_encryption_by_default": [
                    	{
                            "sse_algorithm": "AES256"
                    	}
                	]
            	}
        	]
    	)


app = App()

ProdS3Stack(app, "prod-s3")

app.synth()




