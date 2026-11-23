package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.events.Builder;
import dev.camada.events.Builder.RequestInfo;
import dev.camada.events.Builder.Token;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The SDK conformance cases (contract C6) every server SDK runs: client-IP resolution
 * (camada-all-0vho XFF ports, camada-all-yfc6 peer-first cidrs walk), the Referer scrub and the
 * request's own query scrub (camada-all-ijsa), plus the opt-in token hash (camada-all-29aa). The
 * files live in camada-core/test/fixtures; a missing file fails by name, never skips. No case is
 * skipped here. Configs go through {@link Config#trustedProxy}, the same parse the
 * analyst-delivered tenant config takes.
 */
class SdkConformanceTest {
  @TestFactory
  Stream<DynamicTest> resolveClientIp() {
    Map<String, Object> doc = Json.asMap(Fixtures.readJson("ip/resolve.json"));
    Map<String, Object> configs = Json.asMap(doc.get("configs"));
    List<DynamicTest> out = new ArrayList<>();
    for (Object o : (List<?>) doc.get("cases")) {
      Map<String, Object> c = Json.asMap(o);
      String id = (String) c.get("id");
      String config = (String) c.get("config");
      out.add(
          DynamicTest.dynamicTest(
              id,
              () -> {
                assertTrue(configs.containsKey(config), "unknown config " + config);
                Config.TrustedProxy cfg = Config.trustedProxy(Json.asMap(configs.get(config)));
                assertEquals(
                    c.get("expect"),
                    Ip.resolveClientIp((String) c.get("peer"), (String) c.get("xff"), cfg),
                    id);
              }));
    }
    assertFalse(out.isEmpty(), "ip/resolve.json has no cases");
    return out.stream();
  }

  @TestFactory
  Stream<DynamicTest> refererRedaction() {
    Map<String, Object> doc = Json.asMap(Fixtures.readJson("redact/referer.json"));
    List<DynamicTest> out = new ArrayList<>();
    for (Object o : (List<?>) doc.get("cases")) {
      Map<String, Object> c = Json.asMap(o);
      String id = (String) c.get("id");
      out.add(
          DynamicTest.dynamicTest(
              id,
              () -> {
                List<Map.Entry<String, String>> headers = new ArrayList<>();
                headers.add(new AbstractMap.SimpleEntry<>("accept", "text/html"));
                if (c.get("referer") instanceof String referer) {
                  headers.add(new AbstractMap.SimpleEntry<>("referer", referer));
                }
                RequestInfo req =
                    new RequestInfo("GET", "shop.test", "/api/me", "", headers, "1.2.3.4", "1.1");
                Map<String, Object> ev = Builder.build(req, "sdk-java", "r1", null, false, null);
                assertEquals(c.get("ref"), ev.get("ref"), id);
                String json = Json.stringify(ev);
                if (c.get("absent") instanceof List<?> absent) {
                  for (Object secret : absent) {
                    assertFalse(json.contains((String) secret), id + ": " + secret);
                  }
                }
              }));
    }
    assertFalse(out.isEmpty(), "redact/referer.json has no cases");
    return out.stream();
  }

  @TestFactory
  Stream<DynamicTest> queryRedaction() {
    Map<String, Object> doc = Json.asMap(Fixtures.readJson("redact/query.json"));
    List<DynamicTest> out = new ArrayList<>();
    for (Object o : (List<?>) doc.get("cases")) {
      Map<String, Object> c = Json.asMap(o);
      String id = (String) c.get("id");
      out.add(
          DynamicTest.dynamicTest(
              id,
              () -> {
                List<Map.Entry<String, String>> headers = new ArrayList<>();
                headers.add(new AbstractMap.SimpleEntry<>("accept", "text/html"));
                RequestInfo req =
                    new RequestInfo(
                        "GET",
                        "shop.test",
                        "/api/me",
                        (String) c.get("query"),
                        headers,
                        "1.2.3.4",
                        "1.1");
                Map<String, Object> ev = Builder.build(req, "sdk-java", "r1", null, false, null);
                assertEquals(c.get("q"), ev.get("q"), id);
                String json = Json.stringify(ev);
                if (c.get("absent") instanceof List<?> absent) {
                  for (Object secret : absent) {
                    assertFalse(json.contains((String) secret), id + ": " + secret);
                  }
                }
              }));
    }
    assertFalse(out.isEmpty(), "redact/query.json has no cases");
    return out.stream();
  }

  @TestFactory
  Stream<DynamicTest> tokenHash() {
    Map<String, Object> doc = Fixtures.readMeta("redact/token.json");
    assertEquals(1, ((Number) doc.get("version")).intValue());
    List<?> cases = (List<?>) doc.get("cases");
    assertEquals(22, cases.size());
    return cases.stream()
        .map(
            raw -> {
              Map<String, Object> c = Json.asMap(raw);
              return DynamicTest.dynamicTest(
                  (String) c.get("id"),
                  () -> {
                    Map<String, String> headers = new LinkedHashMap<>();
                    Json.asMap(c.get("headers"))
                        .forEach((name, value) -> headers.put(name, (String) value));
                    String extra =
                        Config.resolveTokenHeader((String) c.get("tokenHeader"), null).name();
                    assertEquals(c.get("credential"), Redact.selectCredential(headers, extra));

                    RequestInfo req =
                        new RequestInfo(
                            "GET",
                            "shop.test",
                            "/api/me",
                            "",
                            new ArrayList<>(headers.entrySet()),
                            "1.2.3.4",
                            "1.1");
                    String key = (String) c.get("key");
                    Map<String, Object> ev =
                        Builder.build(
                            req,
                            "sdk-java",
                            "r1",
                            null,
                            false,
                            null,
                            new Token(extra, value -> Redact.hashToken(value, key)));
                    if (c.get("tk") == null) {
                      assertFalse(ev.containsKey("tk"));
                    } else {
                      assertEquals(c.get("tk"), ev.get("tk"));
                    }
                  });
            });
  }

  @org.junit.jupiter.api.Test
  void fixturesAreVersion3() {
    Map<String, Integer> counts =
        Map.of("ip/resolve.json", 100, "redact/referer.json", 47, "redact/query.json", 39);
    for (Map.Entry<String, Integer> e : counts.entrySet()) {
      Map<String, Object> doc = Json.asMap(Fixtures.readJson(e.getKey()));
      assertEquals(3, ((Number) doc.get("version")).intValue(), e.getKey());
      assertEquals(e.getValue(), ((List<?>) doc.get("cases")).size(), e.getKey());
    }
  }
}
