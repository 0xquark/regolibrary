package armo_builtins
import data.cautils as cautils

# Check if encryption in etcd is enabled for native k8s
deny[msga] {
	apiserverpod := input[_]
    cmd := apiserverpod.spec.containers[0].command
    not cautils.list_contains(cmd, "--encryption-provider-config=")
	path := sprintf("spec.containers[0].command", [format_int(j, 10)])	
	
	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [apiserverpod],
		
		}
	}
}