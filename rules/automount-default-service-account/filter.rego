package armo_builtins

# Fails if user account mount tokens in pod by default
deny [msga]{
    service_accounts := [service_account |  service_account= input[_]; service_account.kind == "ServiceAccount"]
    service_account := service_accounts[_]
	service_account.metadata.name == "default"

    msga := {
	    "alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [service_account.metadata.name, service_account.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": [],
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [service_account]
		}
	}
}    
