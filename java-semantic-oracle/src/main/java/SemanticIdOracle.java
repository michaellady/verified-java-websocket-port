import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

/**
 * Emits compiler-derived semantic identities for a Java source tree using the JDK Compiler Tree
 * API. Identity is taken from {@code javax.lang.model} elements after {@code JavacTask.analyze()},
 * so every binary name, JVM descriptor, and generic signature is produced by javac's own symbol
 * table rather than by text matching.
 *
 * <p>The analyzed tree is treated as quarantined input: annotation processing is disabled
 * ({@code -proc:none}) and no target class is ever loaded or executed.
 */
public final class SemanticIdOracle {

  private SemanticIdOracle() {}

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      System.err.println(
          "usage: SemanticIdOracle <source-root> <output-json> <study-surface-list-file>");
      System.exit(2);
      return;
    }
    Path sourceRoot = Paths.get(args[0]).toAbsolutePath().normalize();
    Path outputPath = Paths.get(args[1]).toAbsolutePath().normalize();
    Path studyListPath = Paths.get(args[2]).toAbsolutePath().normalize();
    String classpath = System.getProperty("oracle.classpath", "");

    Set<String> studySurface = new TreeSet<>();
    for (String line : Files.readAllLines(studyListPath, StandardCharsets.UTF_8)) {
      String trimmed = line.trim();
      if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
        studySurface.add(trimmed);
      }
    }

    List<Path> sources = collectJavaSources(sourceRoot);
    List<FileRecord> fileRecords = new ArrayList<>();
    for (Path source : sources) {
      String relative = toRelative(sourceRoot, source);
      byte[] bytes = Files.readAllBytes(source);
      fileRecords.add(
          new FileRecord(
              relative,
              countPhysicalLines(bytes),
              sha256(bytes),
              studySurface.contains(relative),
              packageOf(relative)));
    }
    fileRecords.sort(Comparator.comparing(record -> record.path));

    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      System.err.println("no system Java compiler available");
      System.exit(3);
      return;
    }
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    List<DeclarationRecord> declarations = new ArrayList<>();
    int errorCount;
    int analyzedTopLevel = 0;

    try (StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
      fileManager.setLocationFromPaths(StandardLocation.SOURCE_PATH, List.of(sourceRoot));
      if (!classpath.isEmpty()) {
        List<Path> classpathEntries = new ArrayList<>();
        for (String entry : classpath.split(java.io.File.pathSeparator)) {
          if (!entry.isEmpty()) {
            classpathEntries.add(Paths.get(entry));
          }
        }
        fileManager.setLocationFromPaths(StandardLocation.CLASS_PATH, classpathEntries);
      }
      Iterable<? extends JavaFileObject> units =
          fileManager.getJavaFileObjectsFromPaths(sources);
      List<String> options = List.of("-proc:none", "-g", "-encoding", "UTF-8", "--release", "17");
      JavacTask task =
          (JavacTask) compiler.getTask(null, fileManager, diagnostics, options, null, units);
      Elements elements = task.getElements();
      Types types = task.getTypes();
      Trees trees = Trees.instance(task);
      SourcePositions positions = trees.getSourcePositions();

      for (Element topLevel : task.analyze()) {
        if (!(topLevel instanceof TypeElement)) {
          continue;
        }
        analyzedTopLevel++;
        collect(
            (TypeElement) topLevel,
            elements,
            types,
            trees,
            positions,
            sourceRoot,
            studySurface,
            declarations);
      }
      errorCount = countErrors(diagnostics);
    }

    declarations.sort(
        Comparator.comparing((DeclarationRecord record) -> record.semanticKey)
            .thenComparing(record -> record.file));

    long productionLines = fileRecords.stream().mapToLong(record -> record.physicalLines).sum();
    long studyFiles = fileRecords.stream().filter(record -> record.inStudySurface).count();
    long studyLines =
        fileRecords.stream()
            .filter(record -> record.inStudySurface)
            .mapToLong(record -> record.physicalLines)
            .sum();

    StringBuilder out = new StringBuilder(1 << 20);
    out.append("{\n");
    out.append("  \"tool\": \"semantic-id-oracle\",\n");
    out.append("  \"tool_version\": \"1.0.0\",\n");
    out.append("  \"identity_source\": ")
        .append(
            quote(
                "javax.lang.model elements from com.sun.source.util.JavacTask.analyze()"
                    + " (JDK Compiler Tree API)"))
        .append(",\n");
    out.append("  \"jdk_version\": ").append(quote(System.getProperty("java.version"))).append(",\n");
    out.append("  \"jdk_vendor\": ").append(quote(System.getProperty("java.vendor"))).append(",\n");
    out.append("  \"javac_options\": [\"-proc:none\", \"-g\", \"-encoding\", \"UTF-8\",")
        .append(" \"--release\", \"17\"],\n");
    out.append("  \"compilation\": {\n");
    out.append("    \"diagnostic_error_count\": ").append(errorCount).append(",\n");
    out.append("    \"analyzed_top_level_types\": ").append(analyzedTopLevel).append(",\n");
    out.append("    \"compilation_unit_count\": ").append(sources.size()).append("\n");
    out.append("  },\n");
    out.append("  \"totals\": {\n");
    out.append("    \"files\": ").append(fileRecords.size()).append(",\n");
    out.append("    \"physical_lines\": ").append(productionLines).append(",\n");
    out.append("    \"study_surface_files\": ").append(studyFiles).append(",\n");
    out.append("    \"study_surface_physical_lines\": ").append(studyLines).append(",\n");
    out.append("    \"declarations\": ").append(declarations.size()).append("\n");
    out.append("  },\n");

    out.append("  \"files\": [\n");
    for (int index = 0; index < fileRecords.size(); index++) {
      FileRecord record = fileRecords.get(index);
      out.append("    {\"path\": ").append(quote(record.path));
      out.append(", \"package\": ").append(quote(record.packageName));
      out.append(", \"physical_lines\": ").append(record.physicalLines);
      out.append(", \"sha256\": ").append(quote(record.sha256));
      out.append(", \"in_study_surface\": ").append(record.inStudySurface).append("}");
      out.append(index + 1 < fileRecords.size() ? ",\n" : "\n");
    }
    out.append("  ],\n");

    out.append("  \"declarations\": [\n");
    for (int index = 0; index < declarations.size(); index++) {
      DeclarationRecord record = declarations.get(index);
      out.append("    {\"semantic_key\": ").append(quote(record.semanticKey));
      out.append(", \"kind\": ").append(quote(record.kind));
      out.append(", \"owner_binary_name\": ").append(quote(record.ownerBinaryName));
      out.append(", \"name\": ").append(quote(record.name));
      out.append(", \"descriptor\": ").append(quote(record.descriptor));
      out.append(", \"generic_signature\": ").append(quote(record.genericSignature));
      out.append(", \"modifiers\": ").append(quoteList(record.modifiers));
      out.append(", \"file\": ").append(quote(record.file));
      out.append(", \"line\": ").append(record.line);
      out.append(", \"in_study_surface\": ").append(record.inStudySurface).append("}");
      out.append(index + 1 < declarations.size() ? ",\n" : "\n");
    }
    out.append("  ]\n");
    out.append("}\n");

    Files.createDirectories(outputPath.getParent());
    Files.write(outputPath, out.toString().getBytes(StandardCharsets.UTF_8));

    PrintStream stdout = System.out;
    stdout.println("files=" + fileRecords.size() + " physical_lines=" + productionLines);
    stdout.println("study_files=" + studyFiles + " study_physical_lines=" + studyLines);
    stdout.println(
        "declarations=" + declarations.size() + " errors=" + errorCount
            + " analyzed_top_level=" + analyzedTopLevel);
    for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
      if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
        System.err.println("ERROR " + diagnostic.getMessage(Locale.ROOT));
      }
    }
    if (errorCount > 0) {
      System.exit(4);
    }
  }

  private static int countErrors(DiagnosticCollector<JavaFileObject> diagnostics) {
    int count = 0;
    for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
      if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
        count++;
      }
    }
    return count;
  }

  private static void collect(
      TypeElement type,
      Elements elements,
      Types types,
      Trees trees,
      SourcePositions positions,
      Path sourceRoot,
      Set<String> studySurface,
      List<DeclarationRecord> sink) {
    String binaryName = elements.getBinaryName(type).toString();
    String file = fileOf(trees, type, sourceRoot);
    boolean inStudy = studySurface.contains(file);
    sink.add(
        new DeclarationRecord(
            binaryName,
            kindOf(type),
            binaryName,
            type.getSimpleName().toString(),
            "L" + binaryName.replace('.', '/') + ";",
            type.asType().toString(),
            modifiersOf(type),
            file,
            lineOf(trees, positions, type),
            inStudy));

    for (Element enclosed : type.getEnclosedElements()) {
      switch (enclosed.getKind()) {
        case CLASS:
        case INTERFACE:
        case ENUM:
        case RECORD:
        case ANNOTATION_TYPE:
          collect(
              (TypeElement) enclosed,
              elements,
              types,
              trees,
              positions,
              sourceRoot,
              studySurface,
              sink);
          break;
        case METHOD:
        case CONSTRUCTOR:
          {
            ExecutableElement executable = (ExecutableElement) enclosed;
            String descriptor = descriptorOf(executable, types);
            String name =
                enclosed.getKind() == ElementKind.CONSTRUCTOR
                    ? "<init>"
                    : executable.getSimpleName().toString();
            sink.add(
                new DeclarationRecord(
                    binaryName + "#" + name + descriptor,
                    kindOf(enclosed),
                    binaryName,
                    name,
                    descriptor,
                    executable.asType().toString(),
                    modifiersOf(enclosed),
                    file,
                    lineOf(trees, positions, enclosed),
                    inStudy));
            break;
          }
        case FIELD:
        case ENUM_CONSTANT:
          {
            VariableElement variable = (VariableElement) enclosed;
            String descriptor = typeDescriptor(types.erasure(variable.asType()));
            sink.add(
                new DeclarationRecord(
                    binaryName + "#" + variable.getSimpleName() + ":" + descriptor,
                    kindOf(enclosed),
                    binaryName,
                    variable.getSimpleName().toString(),
                    descriptor,
                    variable.asType().toString(),
                    modifiersOf(enclosed),
                    file,
                    lineOf(trees, positions, enclosed),
                    inStudy));
            break;
          }
        default:
          break;
      }
    }
  }

  private static String kindOf(Element element) {
    return element.getKind().name();
  }

  private static List<String> modifiersOf(Element element) {
    List<String> names = new ArrayList<>();
    for (Modifier modifier : element.getModifiers()) {
      names.add(modifier.name());
    }
    Collections.sort(names);
    return names;
  }

  private static String descriptorOf(ExecutableElement executable, Types types) {
    StringBuilder builder = new StringBuilder("(");
    for (VariableElement parameter : executable.getParameters()) {
      builder.append(typeDescriptor(types.erasure(parameter.asType())));
    }
    builder.append(')');
    builder.append(typeDescriptor(types.erasure(executable.getReturnType())));
    return builder.toString();
  }

  private static String typeDescriptor(TypeMirror type) {
    switch (type.getKind()) {
      case BOOLEAN:
        return "Z";
      case BYTE:
        return "B";
      case CHAR:
        return "C";
      case SHORT:
        return "S";
      case INT:
        return "I";
      case LONG:
        return "J";
      case FLOAT:
        return "F";
      case DOUBLE:
        return "D";
      case VOID:
        return "V";
      case ARRAY:
        return "[" + typeDescriptor(((ArrayType) type).getComponentType());
      case DECLARED:
        {
          Element element = ((DeclaredType) type).asElement();
          String qualified = flatName((TypeElement) element);
          return "L" + qualified.replace('.', '/') + ";";
        }
      default:
        if (type.getKind() == TypeKind.TYPEVAR) {
          return "Ljava/lang/Object;";
        }
        return "L" + type.toString().replace('.', '/') + ";";
    }
  }

  /** Builds the JVM flat name (Outer$Inner) for a type element. */
  private static String flatName(TypeElement element) {
    StringBuilder simple = new StringBuilder(element.getSimpleName().toString());
    Element enclosing = element.getEnclosingElement();
    while (enclosing instanceof TypeElement) {
      simple.insert(0, ((TypeElement) enclosing).getSimpleName().toString() + "$");
      enclosing = enclosing.getEnclosingElement();
    }
    Element root = element;
    while (root.getEnclosingElement() instanceof TypeElement) {
      root = root.getEnclosingElement();
    }
    String rootQualified = ((TypeElement) root).getQualifiedName().toString();
    int rootDot = rootQualified.lastIndexOf('.');
    String packageName = rootDot >= 0 ? rootQualified.substring(0, rootDot) : "";
    return packageName.isEmpty() ? simple.toString() : packageName + "." + simple;
  }

  private static String fileOf(Trees trees, Element element, Path sourceRoot) {
    var path = trees.getPath(element);
    if (path == null) {
      return "";
    }
    JavaFileObject sourceFile = path.getCompilationUnit().getSourceFile();
    if (sourceFile == null) {
      return "";
    }
    URI uri = sourceFile.toUri();
    if (!"file".equals(uri.getScheme())) {
      return sourceFile.getName();
    }
    return toRelative(sourceRoot, Paths.get(uri).toAbsolutePath().normalize());
  }

  private static long lineOf(Trees trees, SourcePositions positions, Element element) {
    var path = trees.getPath(element);
    if (path == null) {
      return 0L;
    }
    long start =
        positions.getStartPosition(path.getCompilationUnit(), path.getLeaf());
    if (start < 0) {
      return 0L;
    }
    return path.getCompilationUnit().getLineMap().getLineNumber(start);
  }

  private static List<Path> collectJavaSources(Path root) throws IOException {
    try (var stream = Files.walk(root)) {
      return stream
          .filter(Files::isRegularFile)
          .filter(candidate -> candidate.getFileName().toString().endsWith(".java"))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  private static String toRelative(Path root, Path file) {
    return root.relativize(file).toString().replace(java.io.File.separatorChar, '/');
  }

  private static String packageOf(String relativePath) {
    int lastSlash = relativePath.lastIndexOf('/');
    if (lastSlash < 0) {
      return "";
    }
    return relativePath.substring(0, lastSlash).replace('/', '.');
  }

  /** Counts newline bytes, matching {@code wc -l} semantics exactly. */
  private static long countPhysicalLines(byte[] bytes) {
    long count = 0;
    for (byte value : bytes) {
      if (value == (byte) '\n') {
        count++;
      }
    }
    return count;
  }

  private static String sha256(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(bytes);
      StringBuilder builder = new StringBuilder("sha256:");
      for (byte value : hash) {
        builder.append(String.format(Locale.ROOT, "%02x", value));
      }
      return builder.toString();
    } catch (NoSuchAlgorithmException cause) {
      throw new IllegalStateException("SHA-256 unavailable", cause);
    }
  }

  private static String quoteList(List<String> values) {
    StringBuilder builder = new StringBuilder("[");
    for (int index = 0; index < values.size(); index++) {
      builder.append(quote(values.get(index)));
      if (index + 1 < values.size()) {
        builder.append(", ");
      }
    }
    return builder.append(']').toString();
  }

  private static String quote(String value) {
    StringBuilder builder = new StringBuilder("\"");
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"':
          builder.append("\\\"");
          break;
        case '\\':
          builder.append("\\\\");
          break;
        case '\n':
          builder.append("\\n");
          break;
        case '\r':
          builder.append("\\r");
          break;
        case '\t':
          builder.append("\\t");
          break;
        default:
          if (character < 0x20) {
            builder.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
          } else {
            builder.append(character);
          }
      }
    }
    return builder.append('"').toString();
  }

  private static final class FileRecord {
    final String path;
    final long physicalLines;
    final String sha256;
    final boolean inStudySurface;
    final String packageName;

    FileRecord(
        String path, long physicalLines, String sha256, boolean inStudySurface, String packageName) {
      this.path = path;
      this.physicalLines = physicalLines;
      this.sha256 = sha256;
      this.inStudySurface = inStudySurface;
      this.packageName = packageName;
    }
  }

  private static final class DeclarationRecord {
    final String semanticKey;
    final String kind;
    final String ownerBinaryName;
    final String name;
    final String descriptor;
    final String genericSignature;
    final List<String> modifiers;
    final String file;
    final long line;
    final boolean inStudySurface;

    DeclarationRecord(
        String semanticKey,
        String kind,
        String ownerBinaryName,
        String name,
        String descriptor,
        String genericSignature,
        List<String> modifiers,
        String file,
        long line,
        boolean inStudySurface) {
      this.semanticKey = semanticKey;
      this.kind = kind;
      this.ownerBinaryName = ownerBinaryName;
      this.name = name;
      this.descriptor = descriptor;
      this.genericSignature = genericSignature;
      this.modifiers = modifiers;
      this.file = file;
      this.line = line;
      this.inStudySurface = inStudySurface;
    }
  }

  static {
    // Fail fast if the Tree API is unavailable rather than silently degrading to text matching.
    try {
      Class.forName("com.sun.source.util.JavacTask");
    } catch (ClassNotFoundException cause) {
      throw new IllegalStateException("JDK Compiler Tree API unavailable", cause);
    }
  }
}
