package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The minimal JSON the SDK needs (meta, x-camada-config, event batches, beacon bodies): objects
 * keep insertion order, integers come back as Long, everything else as Double, junk throws.
 */
class JsonTest {
  @Test
  void parsesTheShapesTheWireCarries() {
    Object v =
        Json.parse(
            " {\"a\": [1, -2.5, 1e3, true, false, null, \"s\\n\\u00e9\\ud83d\\ude00\"], \"b\": {}} ");
    Map<String, Object> m = Json.asMap(v);
    assertEquals(Arrays.asList(1L, -2.5, 1000.0, true, false, null, "s\né😀"), m.get("a"));
    assertEquals(Map.of(), m.get("b"));
    assertEquals(9007199254740993L, Json.parse("9007199254740993"));
    assertTrue(((Double) Json.parse("1e999")).isInfinite());
    assertEquals(
        Double.NaN, Json.parse("NaN")); // Python's json admits it; the config guard must too
  }

  @Test
  void junkThrowsAndNeverReturnsHalfAValue() {
    for (String bad :
        new String[] {"", "not json", "{", "[1,]", "{\"a\":1,}", "\"unterminated", "01", "[1] x"}) {
      assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
    }
  }

  @Test
  void nestingPastTheCapThrowsLikeJunkInsteadOfOverflowingTheStack() {
    assertEquals(
        List.of(List.of(List.of())), Json.parse("[".repeat(3) + "]".repeat(3))); // nesting is fine
    String atCap = "[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH);
    assertTrue(Json.parse(atCap) instanceof List);
    assertEquals(Map.of("a", Map.of("b", List.of())), Json.parse("{\"a\":{\"b\":[]}}"));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(Json.MAX_DEPTH + 1)));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(32_000)));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":".repeat(32_000) + "1"));
  }

  @Test
  void stringifiesCompactlyInInsertionOrder() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("z", 1L);
    m.put("a", "x\"y\\<\n\001");
    m.put("n", null);
    m.put("d", 2.5);
    m.put("i", 3);
    m.put("l", List.of(true, Map.of("k", 1L)));
    assertEquals(
        "{\"z\":1,\"a\":\"x\\\"y\\\\<\\n\\u0001\",\"n\":null,\"d\":2.5,\"i\":3,\"l\":[true,{\"k\":1}]}",
        Json.stringify(m));
    assertEquals("null", Json.stringify(Double.NaN));
    assertEquals(Json.stringify(m), Json.stringify(Json.parse(Json.stringify(m))));
  }

  @Test
  void asMapReadsOnlyObjects() {
    assertNull(Json.asMap("x"));
    assertNull(Json.asMap(List.of()));
    assertEquals(1L, Json.asMap(Json.parse("{\"a\":1}")).get("a"));
  }
}
