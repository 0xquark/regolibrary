package armo_builtins

import future.keywords.if
import future.keywords.every

# deny if a NodeInstanceRole has a policies not compliant with the following:
# {
#    "Version": "YYY-MM-DD",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "ecr:BatchCheckLayerAvailability",
#                "ecr:BatchGetImage",
#                "ecr:GetDownloadUrlForLayer",
#                "ecr:GetAuthorizationToken"
#            ],
#            "Resource": "*"
#        }
#    ]
# }
deny[msg] {
	resources := input[_]
	resources.kind == "ListEntitiesForPolicies"
	resources.metadata.provider == "eks"

	role_policies := resources.data.rolesPolicies
	node_instance_role_policies := [key | role_policies[key]; contains(role_policies[key].PolicyRoles[_].RoleName, "NodeInstance")]
	print(node_instance_role_policies)

	# check if the policy satisfies the minimum prerequisites
	policies := input[_]
	policies.kind == "PolicyVersion"
	policies.metadata.provider == "eks"

	# allowed action provided by the CIS
	allowed_actions := ["ecr:BatchCheckLayerAvailability",
                		"ecr:BatchGetImage",
                		"ecr:GetDownloadUrlForLayer",
                		"ecr:GetAuthorizationToken"]

	#node_instance_role_policies := ["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]
	some policy in node_instance_role_policies
		some stat, _ in policies.data.policiesDocuments[policy].Statement
			not policies.data.policiesDocuments[policy].Statement[stat].Effect != "Allow"
			not policies.data.policiesDocuments[policy].Statement[stat].Resource != "*"
			sorted_actions := sort(policies.data.policiesDocuments[policy].Statement[stat].Action)
			not sorted_actions != allowed_actions

	msg := {
		"alertMessage": "Cluster has none read-only access to ECR; Review AWS ECS worker node IAM role (NodeInstanceRole) IAM Policy Permissions to verify that they are set and the minimum required level.",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
		}
	}
}
