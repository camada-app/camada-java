package dev.camada;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Config.RemoteConfig;
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
