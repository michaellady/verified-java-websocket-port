JAVA_WEBSOCKET_JAR ?=
RUNTIME_SUPPORT_CP ?=
BUILD_DIR ?= build
JAVAC ?= javac
JAVA ?= java
JAR ?= jar
BOUND_CLASS_TIMESTAMP ?= 202608281716.20
BOUND_METADATA_TIMESTAMP ?= 2026-08-28T17:16:22Z

MAIN_SOURCES := $(sort $(wildcard src/main/java/*.java))
TEST_SOURCES := $(sort $(wildcard src/test/java/*.java))
RUNTIME_CP := $(BUILD_DIR)/test-classes:$(BUILD_DIR)/classes:$(JAVA_WEBSOCKET_JAR)$(if $(RUNTIME_SUPPORT_CP),:$(RUNTIME_SUPPORT_CP))

.PHONY: all build test maven-test run clean require-runtime

all: test

require-runtime:
	@test -n "$(JAVA_WEBSOCKET_JAR)" || (echo "JAVA_WEBSOCKET_JAR is required" >&2; exit 2)
	@test -f "$(JAVA_WEBSOCKET_JAR)" || (echo "JAVA_WEBSOCKET_JAR must name a file" >&2; exit 2)

build: require-runtime
	mkdir -p "$(BUILD_DIR)/classes"
	$(JAVAC) --release 17 -encoding UTF-8 -Xlint:all -Werror \
		-cp "$(JAVA_WEBSOCKET_JAR)" -d "$(BUILD_DIR)/classes" $(MAIN_SOURCES)
	find "$(BUILD_DIR)/classes" -type f -name '*.class' \
		-exec touch -t "$(BOUND_CLASS_TIMESTAMP)" {} +
	mkdir -p "$(BUILD_DIR)/empty"
	$(JAR) --create --file "$(BUILD_DIR)/java-oracle.jar" --main-class OracleMain \
		--date="$(BOUND_METADATA_TIMESTAMP)" -C "$(BUILD_DIR)/empty" .
	$(JAR) --update --file "$(BUILD_DIR)/java-oracle.jar" \
		-C "$(BUILD_DIR)/classes" .

test: build
	mkdir -p "$(BUILD_DIR)/test-classes"
	$(JAVAC) --release 17 -encoding UTF-8 -Xlint:all -Werror \
		-cp "$(BUILD_DIR)/classes:$(JAVA_WEBSOCKET_JAR)" \
		-d "$(BUILD_DIR)/test-classes" $(TEST_SOURCES)
	$(JAVA) -ea -Dslf4j.internal.verbosity=ERROR -cp "$(RUNTIME_CP)" OracleMainTest

maven-test: require-runtime
	mvn --batch-mode --no-transfer-progress test \
		-Djava.websocket.jar="$(abspath $(JAVA_WEBSOCKET_JAR))" \
		-Druntime.support.classpath="$(RUNTIME_SUPPORT_CP)"

run: build
	$(JAVA) -Dslf4j.internal.verbosity=ERROR \
		-cp "$(BUILD_DIR)/java-oracle.jar:$(JAVA_WEBSOCKET_JAR)$(if $(RUNTIME_SUPPORT_CP),:$(RUNTIME_SUPPORT_CP))" \
		OracleMain

clean:
	rm -rf -- "$(BUILD_DIR)"
