package challenge_test

import rego.v1

import data.challenge

## Original test event from CloudTrail:

#{
#    "eventVersion": "1.09",
#    "userIdentity": {
#        "type": "AssumedRole",
#        "principalId": "AROAQUFLQHGYHS5GJVSJE:test",
#        "arn": "arn:aws:sts::123456789012:assumed-role/test/st-access-role",
#        "accountId": "123456789012",
#        "accessKeyId": "ASIAQUFLQHGYPFT42NQZ",
#        "sessionContext": {
#            "sessionIssuer": {
#                "type": "Role",
#                "principalId": "AROAQUFLQHGYHS5GJVSJE",
#                "arn": "arn:aws:iam::123456789012:role/test",
#                "accountId": "123456789012",
#                "userName": "test"
#            },
#            "attributes": {
#                "creationDate": "2024-09-25T14:01:12Z",
#                "mfaAuthenticated": "false"
#            }
#        }
#    },
#    "eventTime": "2024-09-25T14:01:26Z",
#    "eventSource": "s3.amazonaws.com",
#    "eventName": "ListBucket",
#    "awsRegion": "us-east-1",
#    "sourceIPAddress": "1.2.3.4",
#    "userAgent": "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.224-190.876.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]",
#    "requestParameters": {
#        "bucketName": "the-bucket-we-want-to-protect",
#        "Host": "s3.amazonaws.com"
#    },
#    "responseElements": null,
#    "additionalEventData": {
#        "SignatureVersion": "SigV4",
#        "CipherSuite": "TLS_AES_128_GCM_SHA256",
#        "bytesTransferredIn": 0,
#        "AuthenticationMethod": "AuthHeader",
#        "x-amz-id-2": "Vhm02zGIuC1DOpONRmlg8KFlLYPvNBJGfDADsFq/M05SqYzdpnpzxkW018zVpOyDUBew/919lYw=",
#        "bytesTransferredOut": 0
#    },
#    "requestID": "7FTZQT0C5526BRYR",
#    "eventID": "32e2c12c-5ad0-44d5-86b8-22ab0680c533",
#    "readOnly": false,
#    "eventType": "AwsApiCall",
#    "managementEvent": true,
#    "recipientAccountId": "123456789012",
#    "vpcEndpointId": "vpce-f40dc59d",
#    "eventCategory": "Management",
#    "tlsDetails": {
#        "tlsVersion": "TLSv1.3",
#        "cipherSuite": "TLS_AES_128_GCM_SHA256",
#        "clientProvidedHostHeader": "s3.amazonaws.com"
#    }
#}


## Only using the referenced parts of the trail JSON for the testing so it's readable

# ALLOWs

test_expected_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_assumed_role_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_expected_role_with_path_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/path/to/st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_assumed_role_with_path_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/path/to/st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_unrelated_bucket_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/st-access-role"}, "requestParameters": {"bucketName": "some-other-bucket"}}
}

test_different_bucket_allowed if {
	challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/some-role"}, "requestParameters": {"bucketName": "some-other-bucket"}}
}

# BLOCKS

test_not_intended_is_blocked if {
	not challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/some-other-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_same_role_different_account_blocked if {
	not challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::987654321098:role/st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_similar_role_is_blocked if {
	not challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/st-access-role2"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_another_similar_role_is_blocked if {
	not challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/other-st-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}

test_one_more_similar_role_is_blocked if {
	not challenge.allow with input as {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/ast-access-role"}, "requestParameters": {"bucketName": "the-bucket-we-want-to-protect"}}
}
