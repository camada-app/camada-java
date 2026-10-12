package dev.camada.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
 * SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case from
 * camada-core/test/challenge.test.ts via camada-python's test_challenge.py.
 */
public class ChallengeTest {
  static final long DAY_MS = 86_400_000L;
  static final long NOW = 1_800_000_000_000L;
  static final String IP = "203.0.113.9";

  public static String solve(String nonce, int bits) {
    long n = 0;
    while (!Format.powOk(Kit.sha256Hex(nonce + "." + n), bits)) {
      n++;
    }
    return String.valueOf(n);
  }

  public static String solve(String nonce) {
    return solve(nonce, 16);
  }

  @Nested
  class Nonce {
    @Test
    void deterministicPerIpAndUtcDay() {
      Kit kit = new Kit("secret");
      String a = kit.nonce(IP, NOW);
      String b = kit.nonce(IP, NOW + 1000);
      assertEquals(a, b);
      assertEquals(Format.NONCE_HEX, a.length());
      assertTrue(a.matches("[0-9a-f]{32}"));
      assertNotEquals(a, kit.nonce("203.0.113.10", NOW));
      assertNotEquals(a, kit.nonce(IP, NOW + DAY_MS));
      assertNotEquals(a, new Kit("other").nonce(IP, NOW));
    }

    @Test
    void acceptsTodayAndYesterdayRejectsOlderAndForgeries() {
      Kit kit = new Kit("secret");
      String yesterday = kit.nonce(IP, NOW - DAY_MS);
      assertTrue(kit.nonceValid(IP, NOW, kit.nonce(IP, NOW)));
      assertTrue(kit.nonceValid(IP, NOW, yesterday));
      assertFalse(kit.nonceValid(IP, NOW, kit.nonce(IP, NOW - 2 * DAY_MS)));
      assertFalse(kit.nonceValid(IP, NOW, "0".repeat(32)));
      assertFalse(kit.nonceValid(IP, NOW, kit.nonce(IP, NOW).substring(0, 31)));
      assertFalse(kit.nonceValid(null, NOW, kit.nonce(IP, NOW)));
      assertFalse(kit.nonceValid(IP, NOW, null));
    }
  }

  @Nested
  class Token {
    @Test
    void roundTripsWithinTheHourAndExpiresAfter() {
      Kit kit = new Kit("secret");
      String t = kit.issue(IP, NOW);
      assertTrue(kit.tokenValid(IP, NOW + 3_599_000, t));
      assertFalse(kit.tokenValid(IP, NOW + 3_600_000, t));
    }

    @Test
    void boundToTheIpAndUnforgeable() {
      Kit kit = new Kit("secret");
      String t = kit.issue(IP, NOW);
      assertFalse(kit.tokenValid("203.0.113.10", NOW, t));
      String exp = t.substring(0, t.indexOf('.'));
      String mac = t.substring(t.indexOf('.') + 1);
      assertFalse(kit.tokenValid(IP, NOW, exp + "." + "0".repeat(mac.length())));
      assertFalse(kit.tokenValid(IP, NOW, (Long.parseLong(exp) + 1) + "." + mac));
      assertFalse(kit.tokenValid(null, NOW, t)); // no ip: never
      for (String junk : new String[] {null, "", "x", ".mac", "notanumber.mac", "12."}) {
        assertFalse(kit.tokenValid(IP, NOW, junk), String.valueOf(junk));
      }
    }

    @Test
    void refusesAnExpiryFurtherOutThanTheTtl() {
      Kit kit = new Kit("secret");
      String far = kit.issue(IP, NOW + 10_000_000); // minted "in the future": exp > now + TTL
      assertFalse(kit.tokenValid(IP, NOW, far));
    }
  }

  @Nested
  class ProofOfWork {
    @Test
    void acceptsA16BitSolutionAndRejectsAnythingElse() {
      Kit kit = new Kit("secret");
      String nonce = kit.nonce(IP, NOW);
      String sol = solve(nonce);
      assertTrue(kit.solutionOk(nonce, sol));
      assertTrue(kit.verify(IP, NOW, nonce, sol));
      assertFalse(kit.solutionOk(nonce, sol + "1"));
      assertFalse(kit.solutionOk(nonce, "x".repeat(33)));
      assertFalse(kit.solutionOk(nonce, null));
      assertFalse(kit.solutionOk(nonce, ""));
      String forged = "f".repeat(32);
      assertFalse(
          kit.verify(IP, NOW, forged, solve(forged))); // a forged nonce, even with real work
    }

    @Test
    void powOkCountsLeadingZeroBits() {
      assertTrue(Format.powOk("0000ffff", 16));
      assertFalse(Format.powOk("0001ffff", 16));
      assertTrue(Format.powOk("00007fff", 17));
      assertFalse(Format.powOk("0000ffff", 17));
      assertTrue(Format.powOk("0", 4));
      assertFalse(Format.powOk("", 4));
      assertFalse(Format.powOk("000g", 17));
    }
  }

  @Nested
  class Helpers {
    @Test
    void cookieString() {
      assertEquals(
          "_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
          Format.challengeCookie("1.abc", false));
      assertTrue(Format.challengeCookie("1.abc", true).endsWith("; Secure"));
    }

    @Test
    void safeReturnToKeepsOnlyASameSitePath() {
      assertEquals("/a/b?c=1", Format.safeReturnTo("/a/b?c=1"));
      for (String bad :
          new String[] {
            null,
            "",
            "https://evil",
            "//evil",
            "/\\evil",
            "/a b",
            "/é",
            "/" + "a".repeat(2048),
            "relative"
          }) {
        assertEquals("/", Format.safeReturnTo(bad), String.valueOf(bad));
      }
    }

    @Test
    void wantsHtml() {
      assertTrue(Format.wantsHtml("text/html,*/*", null));
      assertTrue(Format.wantsHtml("text/html", "document"));
      assertFalse(Format.wantsHtml("application/json", null));
      assertFalse(Format.wantsHtml("text/html", "empty"));
      assertFalse(Format.wantsHtml(null, null));
    }

    @Test
    void formBodyLastValueWinsAndNeverRaises() {
      assertEquals(
          Map.of("a", "2", "b", "x y", "c", "", "%zz", "%zz"),
          Format.parseFormBody("a=1&b=x+y&a=2&c&%zz=%zz"));
      assertEquals(
          Map.of("nonce", "abc", "solution", "7", "to", "/x?y=1"),
          Format.parseFormBody("nonce=abc&solution=7&to=%2Fx%3Fy%3D1"));
      assertEquals(Map.of(), Format.parseFormBody(""));
      assertEquals(
          Map.of("k", "\uFFFD"),
          Format.parseFormBody("k=%ff")); // undecodable bytes: replaced, never thrown
    }

    @Test
    void escaping() {
      assertEquals("a&lt;b&gt;&amp;&quot;c&#39;", Format.escapeAttr("a<b>&\"c'"));
      assertEquals("\"\\u003c/script>\"", Format.escapeScript("</script>"));
    }
  }

  @Nested
  class PageTest {
    @Test
    void selfContainedAndEscaped() {
      String html = Page.render("ab".repeat(16), "/__camada/challenge", "/x\"><script>");
      assertTrue(html.startsWith("<!doctype html>"));
      // no external assets before the solver
      assertFalse(html.split("<script>")[0].replace("http-equiv", "").contains("http"));
      assertTrue(html.contains("action=\"/__camada/challenge\""));
      assertTrue(html.contains("value=\"/x&quot;&gt;&lt;script&gt;\""));
      assertFalse(html.contains("crypto.subtle"));
      assertTrue(html.contains("__camadaSha256Words"));
      assertTrue(html.contains("shift=16"));
      assertTrue(html.endsWith("</body></html>"));
    }

    @Test
    void difficultyIsClamped() {
      assertTrue(Page.render("a".repeat(32), "/v", "/", 99).contains("shift=0"));
      assertTrue(Page.render("a".repeat(32), "/v", "/", 0).contains("shift=31"));
    }

    @Test
    void byteIdenticalToTheFamilyPage() throws Exception {
      // the page @camada/core serves (src/challenge/page.ts, camada-all-mwpo), pinned by digest:
      // sha256 of challengePage({ nonce: '0'.repeat(32), action: '/__camada/challenge', to: '/' })
      String html = Page.render("0".repeat(32), "/__camada/challenge", "/");
      byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
      assertEquals(
          "c80afc5fe51bae26f1baa7da9bcecc505aa0b62d347f3ac668209bcc75887f22",
          HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
      assertEquals(3810, bytes.length);
    }

    private static String between(String html, String open, String close) {
      int a = html.indexOf(open) + open.length();
      return html.substring(a, html.indexOf(close, a));
    }

    private static String hash(String s) throws Exception {
      return "'sha256-"
          + Base64.getEncoder()
              .encodeToString(
                  MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)))
          + "'";
    }

    @Test
    void inlineScriptNoLongerCarriesTheNonce() {
      // camada-all-y38o: one script (one hash) per bits value; the solver reads the form's nonce
      String a = Page.render("ab".repeat(16), "/v", "/");
      String b = Page.render("cd".repeat(16), "/v", "/x");
      assertEquals(between(a, "<script>", "</script>"), between(b, "<script>", "</script>"));
      assertFalse(between(a, "<script>", "</script>").contains("abab"));
      assertTrue(
          a.contains(
              "<input type=\"hidden\" name=\"nonce\" value=\""
                  + "ab".repeat(16)
                  + "\" id=\"camada-n\">"));
      assertTrue(
          between(a, "<script>", "</script>")
              .contains("document.getElementById('camada-n').value"));
    }

    @Test
    void cspAllowsExactlyItsOwnInlineScriptAndStyle() throws Exception {
      for (int bits : new int[] {1, 12, 16, 32}) {
        String html = Page.render("0".repeat(32), "/v", "/", bits);
        String csp = Page.csp(bits);
        assertTrue(
            csp.contains("script-src " + hash(between(html, "<script>", "</script>")) + ";"));
        assertTrue(csp.contains("style-src " + hash(between(html, "<style>", "</style>")) + ";"));
        assertTrue(csp.contains("default-src 'none'"));
        assertFalse(csp.contains("form-action")); // it would block the redirects after verify's 302
        assertFalse(csp.contains("unsafe"));
      }
      // the same policy @camada/core's challengePageCsp(16) sends
      assertEquals(
          "default-src 'none'; script-src 'sha256-ciEqEwbzJaoB3rni2OdS8TuYa+/yFdFMAkRscUn8z8k='; "
              + "style-src 'sha256-uTQFkKw4mZsBeb9oMeUmhuhVK7WwsKvYVU1JAzADMu0='; "
              + "base-uri 'none'; frame-ancestors 'self'",
          Page.csp());
      assertEquals(Page.csp(32), Page.csp(99)); // clamped like the page
      assertNotEquals(Page.csp(12), Page.csp(16));
    }
  }
}
