package dev.camada;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * The golden snapshot containers live in the camada-core sibling checkout (copied verbatim from
 * edge-analyst, the format owner); the suite fails by name when they are missing rather than
 * skipping, the same stance the web/mkt drift guards take. Surefire's cwd is the project basedir.
 */
public final class Fixtures {
  private Fixtures() {}

  public static Path dir() {
    String env = System.getenv("CAMADA_FIXTURES_DIR");
    return env != null && !env.isEmpty()
        ? Paths.get(env)
        : Paths.get("..", "camada-core", "test", "fixtures");
  }

  public static Path path(String rel) {
    Path p = dir().resolve(rel);
    if (!Files.exists(p)) {
      fail(
          "golden fixture missing: "
              + p.toAbsolutePath().normalize()
              + " (no camada-core checkout? set CAMADA_FIXTURES_DIR)");
    }
    return p;
  }

  public static byte[] readBin(String rel) {
    try {
      return Files.readAllBytes(path(rel));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Object readJson(String rel) {
    try {
      return Json.parse(Files.readString(path(rel), StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Map<String, Object> readMeta(String rel) {
    return Json.asMap(readJson(rel));
  }
}
