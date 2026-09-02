package javabind

import (
	"encoding/json"
	"fmt"
)

// CatalogObligation is one row of the immutable 24-obligation catalog. Only the
// fields this package reads are modelled; the catalog itself is never rewritten
// from these structures.
type CatalogObligation struct {
	ObligationID     string   `json:"obligation_id"`
	Statement        string   `json:"statement"`
	SurfaceIDs       []string `json:"surface_ids"`
	RequiredStrength string   `json:"required_strength"`
	AllowedMethods   []string `json:"allowed_methods"`
}

// CatalogBinding is one row of the catalog's own java_bindings or rust_bindings.
type CatalogBinding struct {
	ObligationID     string `json:"obligation_id"`
	Language         string `json:"language"`
	ProductionSymbol string `json:"production_symbol"`
	SourcePath       string `json:"source_path"`
	SourceSHA256     string `json:"source_sha256"`
	ConnectionState  string `json:"connection_state"`
}

// Catalog is the read-only view this package takes of the immutable catalog.
type Catalog struct {
	CatalogID    string              `json:"catalog_id"`
	Obligations  []CatalogObligation `json:"obligations"`
	JavaBindings []CatalogBinding    `json:"java_bindings"`
}

// DecodeCatalog reads the immutable catalog. Unknown fields are tolerated here
// on purpose: the catalog is owned elsewhere and must not be constrained by this
// package's model of it.
func DecodeCatalog(data []byte) (Catalog, error) {
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("javabind: decode catalog: %w", err)
	}
	if catalog.CatalogID != "us023-formal-obligations" {
		return Catalog{}, fmt.Errorf("javabind: catalog id is %q, not the immutable us023-formal-obligations", catalog.CatalogID)
	}
	if len(catalog.Obligations) != CatalogDenominator {
		return Catalog{}, fmt.Errorf("javabind: catalog declares %d obligations, not %d", len(catalog.Obligations), CatalogDenominator)
	}
	if len(catalog.JavaBindings) != CatalogDenominator {
		return Catalog{}, fmt.Errorf("javabind: catalog declares %d java bindings, not %d", len(catalog.JavaBindings), CatalogDenominator)
	}
	return catalog, nil
}

// Obligation looks one obligation up by id.
func (c Catalog) Obligation(id string) (CatalogObligation, bool) {
	for _, obligation := range c.Obligations {
		if obligation.ObligationID == id {
			return obligation, true
		}
	}
	return CatalogObligation{}, false
}

// JavaBinding looks the catalog's own declared Java binding up by obligation id.
func (c Catalog) JavaBinding(id string) (CatalogBinding, bool) {
	for _, binding := range c.JavaBindings {
		if binding.ObligationID == id {
			return binding, true
		}
	}
	return CatalogBinding{}, false
}

// SymbolDescriptor splits a catalog production symbol into its declaring type's
// simple name, the member simple name, and the JVM descriptor. A symbol that
// names a type rather than a member yields an empty member and descriptor.
func SymbolDescriptor(symbol string) (typeName, memberName, descriptor string) {
	head := symbol
	if index := indexByte(symbol, '('); index >= 0 {
		head = symbol[:index]
		descriptor = symbol[index:]
	}
	lastDot := lastIndexByte(head, '.')
	if lastDot < 0 {
		return head, "", descriptor
	}
	candidate := head[lastDot+1:]
	container := head[:lastDot]
	if descriptor == "" && startsUpper(candidate) {
		// A bare type reference: org.java_websocket.server.WebSocketServer
		return candidate, "", ""
	}
	typeDot := lastIndexByte(container, '.')
	if typeDot < 0 {
		return container, candidate, descriptor
	}
	return container[typeDot+1:], candidate, descriptor
}

func indexByte(text string, target byte) int {
	for i := 0; i < len(text); i++ {
		if text[i] == target {
			return i
		}
	}
	return -1
}

func lastIndexByte(text string, target byte) int {
	for i := len(text) - 1; i >= 0; i-- {
		if text[i] == target {
			return i
		}
	}
	return -1
}

func startsUpper(text string) bool {
	return text != "" && text[0] >= 'A' && text[0] <= 'Z'
}
