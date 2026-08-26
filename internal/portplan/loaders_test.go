package portplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadDocument(t *testing.T, root, name string, target any) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, EvidenceDirectory, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
}

func loadInventory(t *testing.T, root string) SurfaceInventory {
	t.Helper()
	var value SurfaceInventory
	loadDocument(t, root, SurfaceInventoryDocument, &value)
	return value
}

func loadMigration(t *testing.T, root string) MigrationMap {
	t.Helper()
	var value MigrationMap
	loadDocument(t, root, MigrationMapDocument, &value)
	return value
}

func loadDossier(t *testing.T, root string) SeamDossier {
	t.Helper()
	var value SeamDossier
	loadDocument(t, root, SeamDossierDocument, &value)
	return value
}
