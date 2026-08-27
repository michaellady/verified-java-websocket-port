import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** A small, strict JSON reader/writer for the dependency-free oracle boundary. */
final class StrictJson {
  static final int MAX_DEPTH = 32;
  static final int MAX_CONTAINER_ENTRIES = 16_384;

  private StrictJson() {}

  static Object parse(String input) throws ProtocolException {
    Parser parser = new Parser(input);
    Object value = parser.value(0);
    parser.whitespace();
    if (!parser.done()) {
      throw parser.error("INVALID_JSON", "trailing content");
    }
    return value;
  }

  static String write(Object value) {
    StringBuilder out = new StringBuilder();
    append(out, value);
    return out.toString();
  }

  static int utf8Length(Object value) {
    return write(value).getBytes(StandardCharsets.UTF_8).length;
  }

  private static void append(StringBuilder out, Object value) {
    if (value == null) {
      out.append("null");
    } else if (value instanceof String string) {
      string(out, string);
    } else if (value instanceof Boolean || value instanceof Integer || value instanceof Long) {
      out.append(value);
    } else if (value instanceof BigDecimal decimal) {
      out.append(decimal.toPlainString());
    } else if (value instanceof Map<?, ?> map) {
      out.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : new TreeMap<>(stringMap(map)).entrySet()) {
        if (!first) {
          out.append(',');
        }
        first = false;
        string(out, (String) entry.getKey());
        out.append(':');
        append(out, entry.getValue());
      }
      out.append('}');
    } else if (value instanceof Collection<?> collection) {
      out.append('[');
      boolean first = true;
      for (Object item : collection) {
        if (!first) {
          out.append(',');
        }
        first = false;
        append(out, item);
      }
      out.append(']');
    } else {
      throw new IllegalArgumentException("unsupported JSON value: " + value.getClass().getName());
    }
  }

  private static Map<String, Object> stringMap(Map<?, ?> map) {
    Map<String, Object> result = new TreeMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new IllegalArgumentException("JSON object key is not a string");
      }
      result.put(key, entry.getValue());
    }
    return result;
  }

  private static void string(StringBuilder out, String value) {
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20 || Character.isSurrogate(c)) {
            if (Character.isHighSurrogate(c) && i + 1 < value.length()
                && Character.isLowSurrogate(value.charAt(i + 1))) {
              out.append(c).append(value.charAt(++i));
            } else {
              out.append(String.format("\\u%04x", (int) c));
            }
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  private static final class Parser {
    private final String input;
    private int at;

    Parser(String input) {
      this.input = input;
    }

    boolean done() {
      return at == input.length();
    }

    void whitespace() {
      while (!done()) {
        char c = input.charAt(at);
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
          at++;
        } else {
          return;
        }
      }
    }

    Object value(int depth) throws ProtocolException {
      if (depth > MAX_DEPTH) {
        throw error("JSON_DEPTH_LIMIT", "JSON nesting exceeds " + MAX_DEPTH);
      }
      whitespace();
      if (done()) {
        throw error("INVALID_JSON", "expected value");
      }
      return switch (input.charAt(at)) {
        case '{' -> object(depth + 1);
        case '[' -> array(depth + 1);
        case '"' -> string();
        case 't' -> literal("true", Boolean.TRUE);
        case 'f' -> literal("false", Boolean.FALSE);
        case 'n' -> literal("null", null);
        default -> number();
      };
    }

    private Map<String, Object> object(int depth) throws ProtocolException {
      at++;
      Map<String, Object> result = new TreeMap<>();
      whitespace();
      if (take('}')) {
        return result;
      }
      while (true) {
        whitespace();
        if (done() || input.charAt(at) != '"') {
          throw error("INVALID_JSON", "object key must be a string");
        }
        String key = string();
        if (result.containsKey(key)) {
          throw error("DUPLICATE_FIELD", "duplicate object field: " + safe(key));
        }
        whitespace();
        if (!take(':')) {
          throw error("INVALID_JSON", "expected ':' after object key");
        }
        result.put(key, value(depth));
        if (result.size() > MAX_CONTAINER_ENTRIES) {
          throw error("JSON_CONTAINER_LIMIT", "object has too many fields");
        }
        whitespace();
        if (take('}')) {
          return result;
        }
        if (!take(',')) {
          throw error("INVALID_JSON", "expected ',' or '}'");
        }
      }
    }

    private List<Object> array(int depth) throws ProtocolException {
      at++;
      List<Object> result = new ArrayList<>();
      whitespace();
      if (take(']')) {
        return result;
      }
      while (true) {
        result.add(value(depth));
        if (result.size() > MAX_CONTAINER_ENTRIES) {
          throw error("JSON_CONTAINER_LIMIT", "array has too many elements");
        }
        whitespace();
        if (take(']')) {
          return result;
        }
        if (!take(',')) {
          throw error("INVALID_JSON", "expected ',' or ']'");
        }
      }
    }

    private String string() throws ProtocolException {
      at++;
      StringBuilder result = new StringBuilder();
      while (!done()) {
        char c = input.charAt(at++);
        if (c == '"') {
          return result.toString();
        }
        if (c < 0x20) {
          throw error("INVALID_JSON", "unescaped control character in string");
        }
        if (c != '\\') {
          if (Character.isSurrogate(c)) {
            if (Character.isHighSurrogate(c) && !done()
                && Character.isLowSurrogate(input.charAt(at))) {
              result.append(c).append(input.charAt(at++));
              continue;
            }
            throw error("INVALID_UNICODE", "unpaired raw surrogate in JSON string");
          }
          result.append(c);
          continue;
        }
        if (done()) {
          throw error("INVALID_JSON", "unterminated string escape");
        }
        char escaped = input.charAt(at++);
        switch (escaped) {
          case '"', '\\', '/' -> result.append(escaped);
          case 'b' -> result.append('\b');
          case 'f' -> result.append('\f');
          case 'n' -> result.append('\n');
          case 'r' -> result.append('\r');
          case 't' -> result.append('\t');
          case 'u' -> appendUnicode(result);
          default -> throw error("INVALID_JSON", "invalid string escape");
        }
      }
      throw error("INVALID_JSON", "unterminated string");
    }

    private void appendUnicode(StringBuilder result) throws ProtocolException {
      char first = unicodeUnit();
      if (Character.isLowSurrogate(first)) {
        throw error("INVALID_UNICODE", "unpaired low surrogate");
      }
      if (!Character.isHighSurrogate(first)) {
        result.append(first);
        return;
      }
      if (at + 2 > input.length() || input.charAt(at) != '\\' || input.charAt(at + 1) != 'u') {
        throw error("INVALID_UNICODE", "unpaired high surrogate");
      }
      at += 2;
      char second = unicodeUnit();
      if (!Character.isLowSurrogate(second)) {
        throw error("INVALID_UNICODE", "invalid surrogate pair");
      }
      result.append(first).append(second);
    }

    private char unicodeUnit() throws ProtocolException {
      if (at + 4 > input.length()) {
        throw error("INVALID_JSON", "short unicode escape");
      }
      int value = 0;
      for (int i = 0; i < 4; i++) {
        int digit = Character.digit(input.charAt(at++), 16);
        if (digit < 0) {
          throw error("INVALID_JSON", "invalid unicode escape");
        }
        value = (value << 4) | digit;
      }
      return (char) value;
    }

    private Object literal(String token, Object value) throws ProtocolException {
      if (!input.startsWith(token, at)) {
        throw error("INVALID_JSON", "invalid literal");
      }
      at += token.length();
      return value;
    }

    private BigDecimal number() throws ProtocolException {
      int start = at;
      if (take('-') && done()) {
        throw error("INVALID_JSON", "incomplete number");
      }
      if (take('0')) {
        if (!done() && Character.isDigit(input.charAt(at))) {
          throw error("INVALID_JSON", "leading zero in number");
        }
      } else {
        if (done() || input.charAt(at) < '1' || input.charAt(at) > '9') {
          throw error("INVALID_JSON", "invalid number");
        }
        while (!done() && Character.isDigit(input.charAt(at))) {
          at++;
        }
      }
      if (take('.')) {
        int fraction = at;
        while (!done() && Character.isDigit(input.charAt(at))) {
          at++;
        }
        if (fraction == at) {
          throw error("INVALID_JSON", "fraction has no digits");
        }
      }
      if (!done() && (input.charAt(at) == 'e' || input.charAt(at) == 'E')) {
        at++;
        if (!done() && (input.charAt(at) == '+' || input.charAt(at) == '-')) {
          at++;
        }
        int exponent = at;
        while (!done() && Character.isDigit(input.charAt(at))) {
          at++;
        }
        if (exponent == at) {
          throw error("INVALID_JSON", "exponent has no digits");
        }
      }
      try {
        return new BigDecimal(input.substring(start, at));
      } catch (NumberFormatException e) {
        throw error("INVALID_JSON", "invalid number");
      }
    }

    private boolean take(char expected) {
      if (!done() && input.charAt(at) == expected) {
        at++;
        return true;
      }
      return false;
    }

    ProtocolException error(String code, String detail) {
      return new ProtocolException(code, detail + " at character " + at);
    }

    private static String safe(String value) {
      if (value.length() <= 80) {
        return value;
      }
      return value.substring(0, 80);
    }
  }
}
