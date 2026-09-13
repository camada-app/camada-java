package dev.camada;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

/**
 * The first-party beacon is @camada/browser's auto build, vendored as a classpath resource so the
 * jar has no runtime file reads. It must be byte-for-byte the sibling's dist/auto.global.js; the
 * test fails by name (never skips) when that checkout or its build is missing.
 */
class BeaconJsTest {
  static Path dist() {
    String env = System.getenv("CAMADA_BROWSER_DIST");
    return env != null && !env.isEmpty()
        ? Paths.get(env)
        : Paths.get("..", "camada-browser", "dist", "auto.global.js");
  }

  static String sha256(byte[] bytes) throws NoSuchAlgorithmException {
    StringBuilder hex = new StringBuilder();
    for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }

  @Test
  void vendoredBeaconMatchesTheSiblingBuild() throws IOException, NoSuchAlgorithmException {
    Path dist = dist();
    assertTrue(
        Files.exists(dist),
        "beacon build missing: "
            + dist.toAbsolutePath().normalize()
            + " (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)");
    byte[] src = Files.readAllBytes(dist);
    assertArrayEquals(
        src, BeaconJs.BYTES, "run scripts/sync-beacon.sh to re-vendor @camada/browser");
    assertEquals(new String(src, StandardCharsets.UTF_8), BeaconJs.JS);
    assertEquals(sha256(src), BeaconJs.SHA256);
  }

  @Test
  void beaconNamesItsOwnVersionAndPostsToFp() {
    assertTrue(BeaconJs.JS.contains("\"" + BeaconJs.VERSION + "\""));
    assertTrue(BeaconJs.JS.contains("@camada/browser"));
    assertTrue(
        BeaconJs.JS.contains(
            "\"fp\"")); // derives the POST target from the script URL's final segment
  }
}
