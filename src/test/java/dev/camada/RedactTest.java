package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * Redaction is not configurable off: credential-looking query values become ~r, body values never
 * ship, user identifiers are HMAC-hashed inside the SDK.
 */
class RedactTest {
  @Test
  void scrubUrlScrubsTheQueryAndFragmentOnly() {
    // camada-all-ijsa: a Referer carries the previous page's query (reset tokens, OAuth codes)
    assertEquals(
        "https://a.test/reset?token=~r&code=~r",
        Redact.scrubUrl(
            "https://a.test/reset?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.s&code=4/0Ab"));
    assertEquals(
        "https://a.test/p?token=~r#code=~r",
        Redact.scrubUrl("https://a.test/p?token=abc#code=def"));
    assertEquals(
        "https://a.test/cb#access_token=~r&expires_in=3599",
        Redact.scrubUrl("https://a.test/cb#access_token=ya29&expires_in=3599"));
    // the path is not scrubbed
    assertEquals(
        "https://a.test/orders/8812?page=2#reviews",
        Redact.scrubUrl("https://a.test/orders/8812?page=2#reviews"));
    assertEquals("https://a.test/p?", Redact.scrubUrl("https://a.test/p?"));
    assertEquals("/reset?token=~r", Redact.scrubUrl("/reset?token=abc"));
    assertNull(Redact.scrubUrl(null));
  }

  @Test
  void scrubQueryByNameAndByValueShape() {
    assertEquals("?q=hello&token=~r&x=1", Redact.scrubQuery("?q=hello&token=abc&x=1"));
    assertEquals("?api_key=~r&PASSWORD=~r", Redact.scrubQuery("?api_key=k&PASSWORD=p"));
    assertEquals("?t=~r", Redact.scrubQuery("?t=eyJhbGciOi.eyJzdWIiOi.sig"));
    assertEquals("?h=~r", Redact.scrubQuery("?h=" + "a".repeat(32)));
    assertEquals("?b=~r", Redact.scrubQuery("?b=" + "A".repeat(40) + "=="));
    assertEquals("?flag&x=1", Redact.scrubQuery("?flag&x=1")); // a bare name is kept as is
  }

  @Test
  void scrubQueryKeepsShapeAndEmpties() {
    assertEquals("", Redact.scrubQuery(""));
    assertEquals("", Redact.scrubQuery(null));
    assertEquals("?", Redact.scrubQuery("?"));
    assertEquals("a=1&code=~r", Redact.scrubQuery("a=1&code=2")); // no leading ? is fine too
  }

  @Test
  void bodyShapeIsNamesAndSizesOnly() {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("email", "a@b.c");
    body.put("n", 12L);
    body.put("none", null);
    body.put("arr", List.of(1L, 2L));
    Map<String, Integer> expected = new LinkedHashMap<>();
    expected.put("email", 5);
    expected.put("n", 2);
    expected.put("none", 0);
    expected.put("arr", 5);
    assertEquals(expected, Redact.bodyShape(body));
    assertNull(Redact.bodyShape(Arrays.asList(1)));
    assertNull(Redact.bodyShape("str"));
  }

  @Test
  void hashUserIdIsALabelledTruncatedHmac() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("tok".getBytes(), "HmacSHA256"));
    StringBuilder hex = new StringBuilder();
    for (byte b : mac.doFinal("uid:alice@example.com".getBytes())) {
      hex.append(String.format("%02x", b));
    }
    assertEquals(hex.substring(0, 32), Redact.hashUserId("alice@example.com", "tok"));
    assertEquals(32, Redact.hashUserId("x", "tok").length());
  }
}
