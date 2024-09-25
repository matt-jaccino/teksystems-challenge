package challenge

import rego.v1

# By default, deny requests.
default allow := false

allow if {
    regex.match(`^(?:arn:[a-z-]+:iam::123456789012:|arn:[a-z-]+:sts::123456789012:assumed-)role/(?:[a-z0-9]+/)*st-access-role$`, input.userIdentity.arn)
    input.requestParameters.bucketName == "the-bucket-we-want-to-protect"
}

allow if {
    not input.requestParameters.bucketName == "the-bucket-we-want-to-protect"
}
