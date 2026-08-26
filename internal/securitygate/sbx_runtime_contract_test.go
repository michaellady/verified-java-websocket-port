package securitygate

import (
	"slices"
	"testing"
)

func TestMeasuredSbxRuntimeContractMatchesProtectedSupervisor(t *testing.T) {
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Isolation.CPUs != 1 || profile.Isolation.Memory != "1g" || profile.Isolation.MemoryBytes != 1<<30 {
		t.Fatalf("outer sbx bounds drifted: %#v", profile.Isolation)
	}
	wantEnvelope := resources{
		WallSeconds: 60, CPUSeconds: 60, MemoryBytes: 1 << 30, PIDs: 64,
		OpenFiles: 256, OutputBytes: 8 << 20, WorkspaceBytes: 64 << 20,
		CacheBytes: 64 << 20, DiskBytes: 64 << 20, Inodes: 16384,
	}
	if profile.SupervisorLimits != wantEnvelope {
		t.Fatalf("compiled envelope drifted: got=%#v want=%#v", profile.SupervisorLimits, wantEnvelope)
	}
	wantPlan := []string{
		"CACHE_WRITE_DENIED", "CLEAN_EXIT", "CPU_BOUND", "ENV_SENTINEL_ABSENT",
		"FD_BOUND", "MEMORY_BOUND", "NETWORK_SOCKET_DENIED", "OUTPUT_BOUND",
		"PID_BOUND", "PROTECTED_SENTINEL_DENIED", "SESSION_ESCAPE_CLEANUP",
		"SOURCE_WRITE_DENIED", "WALL_BOUND", "WORKSPACE_BOUND", "BENIGN_OPERATION",
	}
	if !slices.Equal(protectedFixedPlan(), wantPlan) {
		t.Fatalf("fixed plan drifted: %q", protectedFixedPlan())
	}
	wantOutcomes := map[string]string{
		"CPU_BOUND": "CPU_PARENT_KILL", "FD_BOUND": "FD_PARENT_KILL",
		"MEMORY_BOUND": "MEMORY_PARENT_KILL", "PID_BOUND": "EXIT_23_RLIMIT_NPROC",
		"SESSION_ESCAPE_CLEANUP": "EXIT_0_UID_SWEEP",
	}
	for id, want := range wantOutcomes {
		_, got, err := sbxDescriptorContract(id)
		if err != nil {
			t.Fatalf("descriptor %s: %v", id, err)
		}
		if got != want {
			t.Fatalf("descriptor %s outcome=%q want=%q", id, got, want)
		}
	}
}
