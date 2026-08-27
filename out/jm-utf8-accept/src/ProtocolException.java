final class ProtocolException extends Exception {
  private static final long serialVersionUID = 1L;

  private final String code;
  private final Integer closeCode;

  ProtocolException(String code, String message) {
    this(code, message, null);
  }

  ProtocolException(String code, String message, Integer closeCode) {
    super(clamp(message));
    this.code = code;
    this.closeCode = closeCode;
  }

  String code() {
    return code;
  }

  Integer closeCode() {
    return closeCode;
  }

  private static String clamp(String value) {
    if (value == null || value.isBlank()) {
      return "unspecified protocol error";
    }
    String singleLine = value.replace('\r', ' ').replace('\n', ' ');
    return singleLine.length() <= 240 ? singleLine : singleLine.substring(0, 240);
  }
}
