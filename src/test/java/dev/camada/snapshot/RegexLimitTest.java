package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Fixtures;
import dev.camada.Json;
import dev.camada.snapshot.Matcher.MatchInput;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Contract regex-limit v1 (camada-all-2pap): a customer `matches` regex runs under a per-match
 * deadline and a per-request budget; over the limit it answers like an over-cap value. Rows come
 * from camada-core's regex-limit-vectors.json (pinned by sha256), never a local copy.
 */
class RegexLimitTest {
  static final String PIN = "ec076bfb26f12f0f90ffa42bb7b975c6f905afdfe01ba2caeedf6295dd533696";
  static final String REL = "regex-limit/regex-limit-vectors.json";
  static final Map<String, Object> V = Fixtures.readMeta(REL);
  static final Duration LOOSE = Duration.ofSeconds(20);

  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> rows(String key) {
    return (List<Map<String, Object>>) (List<?>) V.get(key);
  }

  static Object get(Object m, String k) {
    return Json.asMap(m).get(k);
  }

  static String expand(Object v) {
    if (v == null || v instanceof String) {
      return (String) v;
    }
    Map<String, Object> m = Json.asMap(v);
    return (m.get("prefix") == null ? "" : (String) m.get("prefix"))
        + ((String) m.get("repeat")).repeat(((Number) m.get("times")).intValue())
        + (m.get("suffix") == null ? "" : (String) m.get("suffix"));
  }

  static Matcher build(List<Map<String, Object>> rules) {
    return ParseTest.rulesSnapshot(Json.stringify(rules));
  }

  static boolean hit(Map<String, Object> rule, Map<String, Object> input) {
    MatchInput in =
        new MatchInput(
            (String) input.get("ip"),
            null,
            null,
            null,
            expand(input.get("path")),
            expand(input.get("ua")),
            null);
    return rule.get("id").equals(build(List.of(rule)).match(in).rule());
  }

  @Test
  void vectorsPinned() throws Exception {
    byte[] raw = java.nio.file.Files.readAllBytes(Fixtures.path(REL));
    assertEquals(PIN, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)));
  }

  @Test
  void constants() {
    Map<String, Object> c = Json.asMap(V.get("constants"));
    assertEquals(((Number) c.get("MAX_MATCH_INPUT")).intValue(), Parser.MAX_MATCH_INPUT);
    assertEquals(((Number) c.get("MATCH_BUDGET_MS")).intValue(), Parser.MATCH_BUDGET_MS);
    assertEquals(
        ((Number) c.get("REQUEST_REGEX_BUDGET_MS")).intValue(), Parser.REQUEST_REGEX_BUDGET_MS);
  }

  @TestFactory
  Stream<DynamicTest> overLimit() {
    return rows("over_limit").stream()
        .map(
            r ->
                DynamicTest.dynamicTest(
                    (String) r.get("id"),
                    () -> {
                      Map<String, Object> rule = Json.asMap(r.get("rule"));
                      Map<String, Object> input = Json.asMap(r.get("input"));
                      boolean want = (Boolean) Json.asMap(r.get("hit")).get("budget");
                      assertEquals(
                          want,
                          assertTimeoutPreemptively(LOOSE, () -> hit(rule, input)),
                          (String) r.get("why"));
                    }));
  }

  @TestFactory
  Stream<DynamicTest> refusedFallBackToNative() {
    Map<String, Object> base = Json.asMap(V.get("refused_rule"));
    List<DynamicTest> out = new ArrayList<>();
    for (Map<String, Object> r : rows("refused")) {
      int k = 0;
      for (Object c : (List<?>) r.get("cases")) {
        Map<String, Object> cond = new HashMap<>();
        cond.put("f", base.get("field"));
        cond.put("op", "matches");
        cond.put("v", r.get("pattern"));
        Map<String, Object> rule = new HashMap<>();
        rule.put("id", base.get("id"));
        rule.put("action", base.get("action"));
        rule.put("conds", List.of(cond));
        Map<String, Object> input = new HashMap<>();
        input.put("ip", "8.8.8.8");
        input.put("ua", get(c, "ua"));
        boolean want = (Boolean) Json.asMap(get(c, "hit")).get("native");
        out.add(
            DynamicTest.dynamicTest(
                r.get("id") + "#" + k++, () -> assertEquals(want, hit(rule, input))));
      }
    }
    return out.stream();
  }

  @Test
  void deadlineThrowsAndFindMapsIt() {
    Deadline d = new Deadline("a".repeat(1000), System.nanoTime() - 1);
    assertThrows(
        Deadline.RegexBudgetExceeded.class,
        () -> {
          for (int i = 0; i < 256; i++) {
            d.charAt(0);
          }
        });
    assertEquals(0, new Deadline("abc", 0).subSequence(1, 1).length());
    assertEquals(
        "bc", new Deadline("abc", System.nanoTime() + 1_000_000_000L).subSequence(1, 3).toString());
    Pattern bad = Pattern.compile("(?:(?:a|aa){1,10}){1,10}a\\d");
    String in = "a".repeat(2048);
    assertTrue(assertTimeoutPreemptively(LOOSE, () -> Parser.find(bad, in, true)));
    assertFalse(assertTimeoutPreemptively(LOOSE, () -> Parser.find(bad, in, false)));
    assertTrue(Parser.find(Pattern.compile("^a"), "abc", false)); // a normal match is untouched
  }

  @Test
  void requestBudgetStopsLaterRegexes() {
    Map<String, Object> slow = Json.asMap(rows("over_limit").get(1).get("rule")); // OL2, skip
    Map<String, Object> in = Json.asMap(rows("over_limit").get(1).get("input"));
    List<Map<String, Object>> rules = new ArrayList<>();
    for (int i = 0; i < 3; i++) { // 3 x 50 ms > 100 ms
      Map<String, Object> r = new HashMap<>(slow);
      r.put("id", "cr_slow" + i);
      rules.add(r);
    }
    Map<String, Object> tail = new HashMap<>();
    tail.put("id", "cr_tail");
    tail.put("action", "skip");
    tail.put("conds", List.of(Map.of("f", "ua", "op", "matches", "v", "^a")));
    MatchInput mi = new MatchInput("8.8.8.8", null, null, null, null, expand(in.get("ua")), null);

    List<Map<String, Object>> alone = List.of(tail);
    assertEquals("cr_tail", build(alone).match(mi).rule()); // the tail does match by itself

    List<Map<String, Object>> all = new ArrayList<>(rules);
    all.add(tail);
    Matcher m = build(all);
    assertEquals(null, assertTimeoutPreemptively(LOOSE, () -> m.match(mi)).rule());
    // the budget is per request: the next request starts fresh
    assertEquals("cr_tail", build(alone).match(mi).rule());
  }

  /**
   * camada-all-zpbv: a stored `matches` value that is '' or not a string never matches, over the
   * cap or not.
   */
  @TestFactory
  Stream<DynamicTest> aNonStringMatchesValueNeverMatches() {
    List<Object> vals =
        Arrays.asList(123, 0, true, null, Map.of("x", 1), List.of("^/a"), List.of(123), "");
    String str = "123 0 null true {x=1} [^/a] {\"x\":1} [123]"; // every coerced spelling
    String big = "a".repeat(Parser.MAX_MATCH_INPUT + 1);
    Map<String, Object> blk =
        Map.of(
            "id",
            "cr_blk",
            "action",
            "block",
            "conds",
            List.of(Map.of("f", "ip", "op", "is_not", "v", "1.1.1.1")));
    List<DynamicTest> out = new ArrayList<>();
    for (Object v : vals) {
      for (String f : List.of("ua", "path", "header")) {
        for (boolean over : List.of(false, true)) {
          out.add(
              DynamicTest.dynamicTest(
                  Json.stringify(v) + " on " + f + (over ? " over the cap" : ""),
                  () -> {
                    MatchInput in =
                        new MatchInput(
                            "8.8.8.8",
                            null,
                            null,
                            null,
                            over && f.equals("path") ? "/a/" + str + "/" + big : "/a/" + str,
                            over && f.equals("ua") ? str + " " + big : str,
                            n -> over && f.equals("header") ? str + " " + big : str);
                    Map<String, Object> cond = new HashMap<>();
                    cond.put("f", f);
                    cond.put("op", "matches");
                    cond.put("v", v);
                    if (f.equals("header")) {
                      cond.put("name", "x-h");
                    }
                    Map<String, Object> b =
                        Map.of("id", "cr_b", "action", "block", "conds", List.of(cond));
                    Map<String, Object> sk =
                        Map.of("id", "cr_s", "action", "skip", "conds", List.of(cond));
                    assertFalse(build(List.of(b)).match(in).block());
                    assertEquals("cr_blk", build(List.of(sk, blk)).match(in).rule());
                  }));
        }
      }
    }
    return out.stream();
  }
}
