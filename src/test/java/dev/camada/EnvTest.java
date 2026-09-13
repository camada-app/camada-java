package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Environment wiring: CAMADA_KEY (or the two tokens), the URLs, and the flags. */
class EnvTest {
  @Test
  void keyAndDefaults() {
    Env e = Env.resolve(Map.of("CAMADA_KEY", "tok-a.snap-a"));
    assertEquals("tok-a", e.ingestToken());
    assertEquals("snap-a", e.snapToken());
    assertEquals("tok-a.snap-a", e.secret());
    assertEquals(Env.DEFAULT_INGEST_URL, e.ingestUrl());
    assertEquals(Env.DEFAULT_INGEST_URL + "/snapshot", e.snapshotUrl());
    assertFalse(e.serverless());
    assertNull(e.trustedProxy());
  }

  @Test
  void separateTokensUrlsAndFlags() {
    Env e =
        Env.resolve(
            Map.of(
                "CAMADA_TOKEN", "tok-b",
                "CAMADA_SNAPSHOT_TOKEN", "snap-b",
                "CAMADA_INGEST_URL", "http://localhost:8787/",
                "CAMADA_SNAPSHOT_URL", "http://localhost:8787/snap",
                "CAMADA_SERVERLESS", "1",
                "CAMADA_TRUSTED_PROXY", "hops:1"));
    assertEquals("tok-b", e.ingestToken());
    assertEquals("snap-b", e.snapToken());
    assertEquals("tok-b.snap-b", e.secret()); // no CAMADA_KEY: the two tokens joined
    assertEquals("http://localhost:8787", e.ingestUrl()); // trailing slash trimmed
    assertEquals("http://localhost:8787/snap", e.snapshotUrl());
    assertTrue(e.serverless());
    assertEquals("hops", e.trustedProxy().mode());
    assertEquals(1, e.trustedProxy().hops());
    assertEquals(
        "http://localhost:8787/snapshot",
        Env.resolve(Map.of("CAMADA_KEY", "a.b", "CAMADA_INGEST_URL", "http://localhost:8787"))
            .snapshotUrl());
  }

  @Test
  void missingOrHalfCredentialsAreInert() {
    assertNull(Env.resolve(Map.of()));
    assertNull(Env.resolve(Map.of("CAMADA_KEY", "")));
    assertNull(Env.resolve(Map.of("CAMADA_KEY", "nodot")));
    assertNull(Env.resolve(Map.of("CAMADA_TOKEN", "tok")));
    assertNull(Env.resolve(Map.of("CAMADA_SNAPSHOT_TOKEN", "snap")));
  }
}
