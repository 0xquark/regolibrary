# Welcome to the regolibrary!

The main components of the regolibrary:

**Framework** - a group of controls to test against

**Control** - a potential vulnerability to check, can include multiple rules

**Rule** - a single specific test

These are used by [Kubescape](https://github.com/kubescape/kubescape).

---


## **How to**

### **Add a framework** 

Add `frameworkName.json` file in the `/frameworks` directory

Example of a framework:
```
{
    "name": "DevOpsBest",
    "description": "This framework is recommended for use by devops.",
    "attributes": {
      "armoBuiltin": true
    },
    "controlsNames": [
        "Naked PODs",
        "Containers mounting Docker socket",
        "Image pull policy on latest tag",
        "Label usage for resources",
        "K8s common labels usage",
        "Pods in default namespace",
        "Container hostPort",
        "Resources CPU limit and request",
        "Resources memory limit and request",
        "Configured liveness probe",
        "Configured readiness probe"
    ]
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.
* controlNames - List of controls to run, must be exact name. Copy-paste to be sure.

### **Add a control**

Add `controlName.json` file in the `/controls` directory.

Example of a control:
```
{
    "name": "Pods in default namespace",
    "attributes": {
        "armoBuiltin": true
    },
    "description": "It is recommended to avoid running PODs in cluster without explicit namespace assignment. This control identifies all the PODs running in the default namespace.",
    "remediation": "Create necessary namespaces and move all the PODs from default namespace there.",
    "rulesNames": [
        "pods-in-default-namespace"
    ],
    "long_description": "It is recommended to avoid running PODs in cluster without explicit namespace assignment. This may lead to wrong capabilities and permissions assignment and potential compromises. This control identifies all the PODs running in the default namespace.",
    "test": "Check that there are no pods in the 'default' namespace",
    "id": "C-0061",
    "controlID": "C-0061",
    "baseScore": 3
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.
* `rulesNames` -  List of rules to run, must be exact name. Copy-paste to be sure.

* `long_description`, `test` and other control fields are used mainly in the [documentation](https://hub.armosec.io/docs)

* See [control go struct](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructures.go#L56) for more control fields

### **Add a rule**:

1. Add to `/rules` a new directory with the rule name

2. Add to the rule directory file - `rule.metadata.json`:

Example of rule.metadata.json:
```
{
    "name": "resources-cpu-limit-and-request",
    "attributes": {
      "armoBuiltin": true
    },
    "ruleLanguage": "Rego",
    "match": [
      {
        "apiGroups": [
          ""
        ],
        "apiVersions": [
          "v1"
        ],
        "resources": [
          "Pod"
        ]
      }
    ],
    "ruleDependencies": [
    ],
    "controlConfigInputs": [
      {
        "path": "settings.postureControlInputs.cpu_request_max",
        "name": "cpu_request_max",
        "description": "Ensure CPU max requests are set"
      }
    ],
    "description": "CPU limits and requests are not set.",
    "remediation": "Ensure CPU limits and requests are set.",
    "ruleQuery": "armo_builtins"
}
```
* Attribute `"armoBuiltin": true` - mandatory for armo rules. Only ARMO team members are authorized to create builtin objects.


* See [rule go struct](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructures.go#L37) for further explanations of rule fields
* Optional attributes :
  * `"hostSensorRule": "true"` - indicates that rule gets information from host scanner

  * `"useFromKubescapeVersion"` - add if rule is only supported from a certain Kubescape version. Inclusive.

  * `"useUntilKubescapeVersion"` - add if newer version exists so control doesn’t run both. Inclusive. 

  * `"imageScanRelated": true` - indicates that rule uses information from image scanning

  * `"controlConfigInputs"` - A list the rule uses and can be configured by the user. See example above.


3. Add to the new rule directory a new file - `raw.rego`

    This is where the logic of the rule is. 
    Example of `raw.rego`:
    ```
    package armo_builtins

    deny[msga] {

        pod := input[_]
        pod.kind == "Pod"
        container := pod.spec.containers[i]
        container.securityContext.privileged == true
        path := sprintf("containers[%d].securityContext.privileged", [i])

        msga := {
            "alertMessage": sprintf("pod: %v is defined as privileged", [pod.metadata.name]),
            "packagename": "armo_builtins",
            "fixPaths": [],
            "failedPaths": path,
            "alertObject": {
                "k8sApiObjects": [pod]
            }
        }
    }
    ```
    Use [opa rego reference](https://www.openpolicyagent.org/docs/latest/policy-reference/) for help with syntax

    See struct of a [rule response](https://github.com/kubescape/opa-utils/blob/master/reporthandling/datastructuresv1.go#L23)


4. Add a test for the new rule (and run it!). See how to add a test [here](/rules-tests/README.md) and how to run it [here](/testrunner/README.md)

5. Add `filter.rego` if needed - If exists, the filter is run by Kubescape to calculate ‘all resources’ = the number of potential resources to fail. It affects the risk score. Needed in cases where rule asks for resources that are not potential to fail, eg- if a rule asks for pods and service accounts to see if they are connected but only fails the pods, we would create a filter rego that returns only pods.



## Support
Reach out if you have any questions:

* [Open an issue](https://github.com/kubescape/regolibrary/issues/new/choose)
* [Join us](https://discord.com/invite/WKZRaCtBxN) in the discussion on our discord server!

We aren't open for contributions currently, but feel free to contact us with suggestions :)

---

### Our frameworks include:
#### [NSA Framework](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

#### [MITRE ATT&CK® Framework](https://www.microsoft.com/security/blog/wp-content/uploads/2021/03/Matrix-1536x926.png)

#### [CIS Framework](https://workbench.cisecurity.org/benchmarks/8973)