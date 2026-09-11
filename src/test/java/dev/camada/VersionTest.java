package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The SDK's wire identity (SDK-03): x-camada-sdk: @camada/java/<version>. One literal in
 * Version.java and one in pom.xml; the sibling drift guards parse the pom the way they parse a
 * package.json, so the two must agree.
 */
class VersionTest {
  // edge-analyst src/freshness.js SDK_RE: anything else is silently dropped from sdk_versions.
  static final Pattern ANALYST_SDK_RE =
      Pattern.compile(
          "^@?[a-z0-9._-]+(/[a-z0-9._-]+)?/\\d+\\.\\d+\\.\\d+[a-z0-9.-]*$",
          Pattern.CASE_INSENSITIVE);
  // what camada-backend / camada-web / camada-mkt read out of this repo's pom.xml
  static final Pattern POM_VERSION =
      Pattern.compile("<artifactId>camada</artifactId>\\s*<version>([^<]+)</version>");

  @Test
  void pomVersionMatchesTheLiteral() throws IOException {
    String pom = Files.readString(Paths.get("pom.xml"), StandardCharsets.UTF_8);
    Matcher m = POM_VERSION.matcher(pom);
    assertTrue(m.find(), "pom.xml must carry <artifactId>camada</artifactId><version>…</version>");
    assertEquals(m.group(1), Version.VERSION);
  }

  @Test
  void sdkIdIsTheFamilyWireIdentity() {
    assertEquals("@camada/java/" + Version.VERSION, Version.SDK_ID);
    assertTrue(ANALYST_SDK_RE.matcher(Version.SDK_ID).matches());
    assertTrue(Version.SDK_ID.length() <= 64);
  }
}
