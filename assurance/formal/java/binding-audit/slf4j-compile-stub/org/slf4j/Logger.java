/*
 * COMPILE-ONLY STUB. Not production code, not part of any proof.
 *
 * The pinned promoted input `slf4j-api-2.0.13`
 * (sha256:e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9,
 * recorded in evidence/intake/java-intake-manifest.json) is NOT present on
 * this host, and this lane is forbidden from downloading it. This stub exists
 * solely so that `javac` can produce class files for the six shipped types
 * that reference org.slf4j, so that `javap -p -s` can read their descriptors
 * for the catalog binding audit.
 *
 * SOUNDNESS NOTE: org.slf4j appears in the shipped source only as the type of
 * a private instance field (`private final Logger log`) and in call
 * statements inside method bodies. It appears in NO method signature of any
 * symbol audited by the binding-audit script. Substituting this stub for the
 * real jar therefore cannot change any descriptor this audit reads.
 *
 * No JBMC proof in this lane uses these classes: the J1 close-status-code
 * harness compiles the CloseFrame dependency closure, which does not touch
 * org.slf4j at all.
 */
package org.slf4j;

public interface Logger {
  boolean isTraceEnabled();
  void trace(String msg);
  void trace(String format, Object arg);
  void trace(String format, Object arg1, Object arg2);
  void trace(String format, Object... args);
  void trace(String msg, Throwable t);
  void debug(String msg);
  void debug(String format, Object arg);
  void debug(String format, Object arg1, Object arg2);
  void debug(String format, Object... args);
  void debug(String msg, Throwable t);
  void info(String msg);
  void info(String format, Object arg);
  void info(String format, Object arg1, Object arg2);
  void info(String format, Object... args);
  void info(String msg, Throwable t);
  void warn(String msg);
  void warn(String format, Object arg);
  void warn(String format, Object arg1, Object arg2);
  void warn(String format, Object... args);
  void warn(String msg, Throwable t);
  void error(String msg);
  void error(String format, Object arg);
  void error(String format, Object arg1, Object arg2);
  void error(String format, Object... args);
  void error(String msg, Throwable t);
}
