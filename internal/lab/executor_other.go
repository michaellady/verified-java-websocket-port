//go:build !darwin

package lab

func ExecuteSandbox(plan SandboxPlan, root *AcceptedRoot) (*SandboxReceipt, error) {
	if _, err := BuildExecutionSpec(plan, root); err != nil {
		return nil, err
	}
	return nil, finding("PLATFORM_EXECUTOR_UNSUPPORTED", "$.sandbox", "the verified executor currently requires Darwin sandbox-exec or the fixed Docker controller")
}

func RunSandboxChild(arguments []string) (bool, int) { return false, 0 }
