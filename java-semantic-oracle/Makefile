JAVA_SOURCE_ROOT ?=
SLF4J_API_JAR ?=
OUTPUT ?= build/semantic-ids.json
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

build:
	mkdir -p "$(BUILD_DIR)/classes"
	$(JAVAC) --release 17 -encoding UTF-8 -d "$(BUILD_DIR)/classes" $(MAIN_SOURCES)

run: require-inputs build
	$(JAVA) -Doracle.classpath="$(SLF4J_API_JAR)" \
		-cp "$(BUILD_DIR)/classes" SemanticIdOracle \
		"$(JAVA_SOURCE_ROOT)" "$(OUTPUT)" "$(STUDY_SURFACE)"

clean:
	rm -rf -- "$(BUILD_DIR)"
