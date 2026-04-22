package main

import rego.v1

# Validate that every Deployment container and initContainer effectively runs
# as non-root, either by setting securityContext.runAsNonRoot=true itself or
# by inheriting a pod-level default.
pod_run_as_non_root_default if {
  object.get(object.get(input.spec.template.spec, "securityContext", {}), "runAsNonRoot", false) == true
}
container_run_as_non_root(container) if {
  object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null) == true
}
container_run_as_non_root(container) if {
  object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null) == null
  pod_run_as_non_root_default
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container_run_as_non_root(container)
  msg := sprintf("Deployment %v container %v must set securityContext.runAsNonRoot to true or inherit it from the pod securityContext", [input.metadata.name, container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.initContainers[_]
  not container_run_as_non_root(container)
  msg := sprintf("Deployment %v initContainer %v must set securityContext.runAsNonRoot to true or inherit it from the pod securityContext", [input.metadata.name, container.name])
}