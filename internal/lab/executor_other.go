//go:build !darwin

package lab

func ControlledCanaryPlanDigest(request ControlledCanaryRequest) (string, error) {
	if err := validateControlledCanaryRequest(request); err != nil {
		return "", err
	}
	return "", finding("PLATFORM_EXECUTOR_UNSUPPORTED", "$.controlled_canary", "CONTROLLED_CANARY requires Darwin sandbox-exec")
}

func ExecuteControlledCanary(request ControlledCanaryRequest) (*ControlledCanaryReceipt, error) {
	if _, err := ControlledCanaryPlanDigest(request); err != nil {
		return nil, err
	}
	return nil, finding("PLATFORM_EXECUTOR_UNSUPPORTED", "$.controlled_canary", "CONTROLLED_CANARY requires Darwin sandbox-exec")
}

func ExecuteSandbox(plan SandboxPlan, root *AcceptedRoot) (*SandboxReceipt, error) {
	if _, err := BuildExecutionSpec(plan, root); err != nil {
		return nil, err
	}
	return nil, finding("PLATFORM_EXECUTOR_UNSUPPORTED", "$.sandbox", "the verified executor currently requires Darwin sandbox-exec or the fixed Docker controller")
}

func RunSandboxChild(arguments []string) (bool, int) { return false, 0 }
