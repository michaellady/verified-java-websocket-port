JAVA_SOURCE_ROOT ?=
SLF4J_API_JAR ?=
# Identity of the only permitted non-JDK compile input: the exact digest US-002 qualified
# (internal/lab/autobahn_endpoint.go AutobahnSLF4JAPIDigest). javac never runs against
# different bytes.
SLF4J_SHA256 := e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9
OUTPUT ?= ../evidence/intake/semantic-id-oracle.json
STUDY_SURFACE ?= study-surface.txt
BUILD_DIR ?= build
JAVAC ?= javac
JAVA ?= java

MAIN_SOURCES := $(sort $(wildcard src/main/java/*.java))

.PHONY: all build run clean require-inputs

all: run

require-inputs:
	@test -n "$(JAVA_SOURCE_ROOT)" || (echo "JAVA_SOURCE_ROOT is required" >&2; exit 2)
	@test -d "$(JAVA_SOURCE_ROOT)" || (echo "JAVA_SOURCE_ROOT must name a directory" >&2; exit 2)
	@test -n "$(SLF4J_API_JAR)" || (echo "SLF4J_API_JAR is required" >&2; exit 2)
	@test -f "$(SLF4J_API_JAR)" || (echo "SLF4J_API_JAR must name a file" >&2; exit 2)
	@actual=$$(shasum -a 256 "$(SLF4J_API_JAR)" | awk '{print $$1}'); \
	 test "$$actual" = "$(SLF4J_SHA256)" || (echo "SLF4J_API_JAR sha256 $$actual does not" \
	   "match the US-002-qualified digest $(SLF4J_SHA256); refusing to run javac" >&2; exit 2)

build:
	mkdir -p "$(BUILD_DIR)/classes"
	$(JAVAC) --release 17 -encoding UTF-8 -d "$(BUILD_DIR)/classes" $(MAIN_SOURCES)

run: require-inputs build
	$(JAVA) -Doracle.classpath="$(SLF4J_API_JAR)" \
		-cp "$(BUILD_DIR)/classes" SemanticIdOracle \
		"$(JAVA_SOURCE_ROOT)" "$(OUTPUT)" "$(STUDY_SURFACE)"

clean:
	rm -rf -- "$(BUILD_DIR)"
