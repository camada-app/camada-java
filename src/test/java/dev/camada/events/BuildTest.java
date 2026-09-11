package dev.camada.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.events.Builder.RequestInfo;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The wire event reproduces the collector's record(); HDRS bit order is pinned by the shared
 * fixture (ConformanceTest) — here the derived counters and the credential rules.
 */
class BuildTest {
  static List<Map.Entry<String, String>> headers(String... kv) {
    List<Map.Entry<String, String>> out = new ArrayList<>();
    for (int i = 0; i < kv.length; i += 2) {
      out.add(new AbstractMap.SimpleEntry<>(kv[i], kv[i + 1]));
    }
    return out;
  }

  static RequestInfo req(List<Map.Entry<String, String>> headers, String query, String ip) {
    return new RequestInfo("GET", "x.test", "/p", query, headers, ip, "1.1");
  }

  @Test
  void authSchemeOnlyEverShipsAScheme() {
    assertEquals("Bearer", Builder.authScheme("Bearer abc.def"));
    assertEquals("Basic", Builder.authScheme("Basic dXNlcjpwYXNz"));
    assertNull(Builder.authScheme("rawtoken"));
    assertNull(Builder.authScheme(" Bearer x"));
    assertNull(Builder.authScheme("a".repeat(17) + " x"));
    assertNull(Builder.authScheme(null));
  }

  @Test
  void eventFieldsAndCounters() {
    List<Map.Entry<String, String>> headers =
        headers(
            "Accept", "text/html",
            "Cookie", "a=1; b=2",
            "Authorization", "Bearer t",
            "Accept", "*/*",
            "User-Agent", "ua");
    Map<String, Object> ev =
        Builder.build(
            req(headers, "?x=1&token=t&&y", "1.2.3.4"), "sdk-java", "r1", "s1", true, null);
    assertEquals("sdk-java", ev.get("tap"));
    assertEquals("r1", ev.get("rid"));
    assertEquals("s1", ev.get("sid"));
    assertEquals(1, ev.get("ns"));
    assertEquals("GET", ev.get("m"));
    assertEquals("x.test", ev.get("h"));
    assertEquals("/p", ev.get("p"));
    assertEquals("HTTP/1.1", ev.get("proto"));
    assertEquals("?x=1&token=~r&&y", ev.get("q"));
    assertEquals(3, ev.get("qn"));
    assertEquals("text/html", ev.get("acc")); // first occurrence wins
    assertEquals("Bearer", ev.get("auth"));
    assertEquals(2, ev.get("ck"));
    assertEquals(5, ev.get("hn"));
    int hb = 0;
    for (Map.Entry<String, String> h : headers) {
      hb += h.getKey().length() + h.getValue().length();
    }
    assertEquals(hb, ev.get("hb"));
    assertEquals("accept,cookie,authorization,accept,user-agent", ev.get("hord"));
    long hm =
        (1L << Builder.HDRS.indexOf("accept"))
            | (1L << Builder.HDRS.indexOf("cookie"))
            | (1L << Builder.HDRS.indexOf("authorization"));
    assertEquals(hm, ev.get("hm"));
    assertEquals("ua", ev.get("ua"));
    assertTrue(ev.containsKey("st") && ev.get("st") == null);
    assertTrue(ev.containsKey("dur") && ev.get("dur") == null);
    assertTrue(ev.get("ts") instanceof Long);
    assertFalse(ev.containsKey("ja4"));
    assertEquals(
        List.of(
            "tap", "rid", "sid", "ns", "ts", "ip", "proto", "m", "h", "p", "q", "qn", "ct", "cl",
            "ua", "chua", "chmob", "chplat", "acc", "lang", "fs", "fm", "fd", "fu", "ref", "org",
            "xrw", "auth", "hm", "hn", "hb", "ck", "hord", "st", "dur"),
        new ArrayList<>(ev.keySet()));
  }

  @Test
  void eventWithoutHeadersOrIp() {
    Map<String, Object> ev =
        Builder.build(req(List.of(), "", null), "sdk-java", "r", null, false, null);
    assertNull(ev.get("ip"));
    assertNull(ev.get("sid"));
    assertEquals(0, ev.get("ns"));
    assertEquals(0L, ev.get("hm"));
    assertEquals(0, ev.get("hn"));
    assertEquals(0, ev.get("hb"));
    assertEquals(0, ev.get("ck"));
    assertEquals("", ev.get("hord"));
    assertEquals(0, ev.get("qn"));
    assertEquals("", ev.get("q"));
    Map<String, Object> ja4 =
        Builder.build(
            new RequestInfo("GET", "x.test", "/p", null, null, null, null),
            "sdk-java",
            "r",
            null,
            false,
            "t13d");
    assertEquals("t13d", ja4.get("ja4"));
    assertNull(ja4.get("proto"));
  }

  @Test
  void hordAndQueryAreCapped() {
    List<Map.Entry<String, String>> many = new ArrayList<>();
    for (int i = 0; i < 1000; i++) {
      many.add(new AbstractMap.SimpleEntry<>("x-" + i, "v"));
    }
    Map<String, Object> ev =
        Builder.build(req(many, "?" + "a".repeat(600), null), "sdk-java", "r", null, false, null);
    assertEquals(2048, ((String) ev.get("hord")).length());
    assertEquals(512, ((String) ev.get("q")).length());
  }
}
