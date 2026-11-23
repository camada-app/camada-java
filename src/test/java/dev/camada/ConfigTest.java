package dev.camada;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Config.RemoteConfig;
import dev.camada.Config.TokenHeader;
import dev.camada.Config.TrustedProxy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConfigTest {
  @Test
  void keySplitsOnTheFirstDot() {
    assertArrayEquals(
        new String[] {"tok-acme", "snap-acme"}, Config.parseKey("tok-acme.snap-acme"));
    assertArrayEquals(new String[] {"a", "b.c"}, Config.parseKey("a.b.c"));
  }

  @Test
  void keyRejectsMissingHalves() {
    for (String bad : new String[] {null, "", "nodot", ".snap", "tok."}) {
      assertNull(Config.parseKey(bad), String.valueOf(bad));
    }
  }

  @Test
  void tokenHashUsesAnExplicitOptionOrExactlyOneFromTheEnv() {
    assertTrue(Config.tokenHash(true, "0"));
    assertFalse(Config.tokenHash(false, "1"));
    assertTrue(Config.tokenHash(null, "1"));
    assertFalse(Config.tokenHash(null, null));
    assertFalse(Config.tokenHash(null, "true"));
    assertFalse(Config.tokenHash(null, " 1"));
  }

  @Test
  void tokenHeaderValidatesTheSelectedNameWithoutFallingBackOnInvalidOptions() {
    String env = "X-Env-Key";
    assertEquals(new TokenHeader(null, false), Config.resolveTokenHeader("", null));
    assertEquals(new TokenHeader("x-env-key", false), Config.resolveTokenHeader(null, env));
    assertEquals(new TokenHeader("x-env-key", false), Config.resolveTokenHeader("", env));
    assertEquals(new TokenHeader("x-api-key", false), Config.resolveTokenHeader("X-Api-Key", env));
    assertEquals(new TokenHeader(null, true), Config.resolveTokenHeader(null, "bad_name"));
    for (String invalid :
        List.of(
            "bad_name",
            "X-Key\n",
            "X-\u212Aey",
            "x".repeat(65),
            "Authorization",
            "Cookie",
            "Set-Cookie")) {
      assertEquals(new TokenHeader(null, true), Config.resolveTokenHeader(invalid, env), invalid);
    }
  }

  @Test
  void remoteConfigReadsTheWhitelistedShapeAndIgnoresJunk() {
    RemoteConfig c =
        Config.remoteConfig(
            Json.parse(
                "{\"tenant\":\"acme\",\"beacon\":false,\"sample\":0.5,\"exclude\":[\"/health\"],"
                    + "\"trusted_proxy\":{\"mode\":\"hops\",\"hops\":2},\"poll_seconds\":7}"));
    assertEquals("acme", c.tenant());
    assertEquals(Boolean.FALSE, c.beacon());
    assertEquals(0.5, c.sample());
    assertEquals(List.of("/health"), c.exclude());
    assertEquals(new TrustedProxy("hops", 2, List.of()), c.trustedProxy());
    assertEquals(7.0, c.pollSeconds());
    assertNull(Config.remoteConfig(Json.parse("[1]")));
    assertNull(Config.remoteConfig("x"));
    RemoteConfig empty = Config.remoteConfig(Map.of());
    assertNull(empty.beacon());
    assertNull(empty.sample());
    assertTrue(empty.exclude().isEmpty());
    assertNull(empty.trustedProxy());
    assertNull(empty.pollSeconds());
    // a trusted_proxy the server would never send is read as absent, never as trust
    assertNull(
        Config.remoteConfig(Json.parse("{\"trusted_proxy\":{\"mode\":\"hops\",\"hops\":\"x\"}}"))
            .trustedProxy());
    assertEquals(
        new TrustedProxy("cidrs", 0, List.of("10.0.0.0/8")),
        Config.remoteConfig(
                Json.parse("{\"trusted_proxy\":{\"mode\":\"cidrs\",\"cidrs\":[\"10.0.0.0/8\",7]}}"))
            .trustedProxy());
    // a non-numeric poll_seconds or sample is absent, not zero
    RemoteConfig junk =
        Config.remoteConfig(Json.parse("{\"poll_seconds\":\"soon\",\"sample\":\"all\"}"));
    assertNull(junk.pollSeconds());
    assertNull(junk.sample());
  }
}
