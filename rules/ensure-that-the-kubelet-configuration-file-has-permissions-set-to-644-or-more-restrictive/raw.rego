package armo_builtins

import data.cautils as cautils
import future.keywords.in

deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
	is_kubelet_info(obj)

	file_obj_path := ["data", "configFile"]
	file := object.get(obj, file_obj_path, false)

	# Actual permissions test    
	allowed_perms := 420 # == 0o644
	not cautils.unix_permissions_allow(allowed_perms, file.permissions)

	# Build the message
	# filter out irrelevant host-sensor data
	obj_filtered := json.filter(obj, [
		concat("/", file_obj_path),
		"apiVersion",
		"kind",
		"metadata",
	])

	alert := sprintf("the permissions of %s are too permissive. maximum allowed: %o. actual: %o", [file.path, allowed_perms, file.permissions])
	msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chmod %o %s", [allowed_perms, file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj_filtered},
	}
}

is_kubelet_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "KubeletInfo"
}
