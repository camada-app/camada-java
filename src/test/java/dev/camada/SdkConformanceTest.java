package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.events.Builder;
import dev.camada.events.Builder.RequestInfo;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The SDK conformance cases (contract C6) every server SDK runs: client-IP resolution
 * (camada-all-0vho XFF ports, camada-all-yfc6 peer-first cidrs walk) and the Referer scrub
 * (camada-all-ijsa). The files live in camada-core/test/fixtures; a missing file fails by name,
 * never skips. No case is skipped here. Configs go through {@link Config#trustedProxy}, the same
 * parse the analyst-delivered tenant config takes.
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
}
