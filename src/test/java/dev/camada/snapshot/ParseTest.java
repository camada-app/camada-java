package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Fixtures;
import dev.camada.Json;
import dev.camada.snapshot.Matcher.MatchInput;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Container handling the golden cases do not reach: malformed input, the advisory version byte, and
 * the rule-compilation rules (drop, never guess).
 */
class ParseTest {
  static final byte[] V4 = Fixtures.readBin("blk3/v4-basic.bin");
  static final Map<String, Object> V4_META = Fixtures.readMeta("blk3/v4-basic.meta.json");

  /** A section: type + words. */
  record Section(int type, int... words) {}

  /** A tiny BLK container: header then the sections back to back. */
  static byte[] container(int magic, Section... sections) {
    List<Integer> header = new ArrayList<>(List.of(magic, sections.length));
    List<Integer> body = new ArrayList<>();
    int off = 2 + sections.length * 3;
    for (Section s : sections) {
      header.addAll(List.of(s.type(), off, s.words().length));
      for (int w : s.words()) {
        body.add(w);
      }
      off += s.words().length;
    }
    ByteBuffer b =
        ByteBuffer.allocate((header.size() + body.size()) * 4).order(ByteOrder.LITTLE_ENDIAN);
    header.forEach(b::putInt);
    body.forEach(b::putInt);
    return b.array();
  }

  static byte[] words(int... w) {
    ByteBuffer b = ByteBuffer.allocate(w.length * 4).order(ByteOrder.LITTLE_ENDIAN);
    for (int x : w) {
      b.putInt(x);
    }
    return b.array();
  }

  static Map<String, Object> meta(String json) {
    return Json.asMap(Json.parse(json));
  }

  @Test
  void badMagicAndTruncationRaise() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Parser.parse("nope".getBytes(), meta("{\"version\":\"1\"}")));
    // claims 3 sections, has none
    assertThrows(
        IllegalArgumentException.class,
        () -> Parser.parse(words(0x424C4B35, 3), meta("{\"version\":\"1\"}")));
    // section runs past the end
    assertThrows(
        IllegalArgumentException.class,
        () -> Parser.parse(words(0x424C4B35, 1, 10, 5, 100), meta("{\"version\":\"1\"}")));
  }

  @Test
  void unalignedTailIsDroppedNotFatal() {
    byte[] plus = Arrays.copyOf(V4, V4.length + 1);
    plus[V4.length] = 1;
    assertEquals(4, Parser.parse(plus, V4_META).format());
  }

  @Test
  void byteBufferAndArrayInputs() {
    assertEquals(
        "ip4",
        new Matcher(Parser.parse(V4, V4_META)).match(MatchInput.ip("203.0.113.66")).reason());
    ByteBuffer slice = ByteBuffer.wrap(Arrays.copyOf(V4, V4.length + 8), 0, V4.length).slice();
    assertEquals(
        "ip4",
        new Matcher(Parser.parse(slice, V4_META)).match(MatchInput.ip("203.0.113.66")).reason());
  }

  @Test
  void v3MagicStillReadsV4Sections() {
    // the version byte is advisory: an allow range under a BLK3 magic still allows
    int n = (192 << 24) | (2 << 8) | 20;
    byte[] bin3 = container(0x424C4B33, new Section(10, n, n));
    var r =
        new Matcher(Parser.parse(bin3, meta("{\"version\":\"x\"}")))
            .match(MatchInput.ip("192.0.2.20"));
    assertTrue(r.allowed());
    assertEquals("ip4", r.reason());
    assertEquals(3, Parser.parse(bin3, meta("{\"version\":\"x\"}")).format());
  }

  static Matcher rulesSnapshot(String rulesJson, Section... sections) {
    return new Matcher(
        Parser.parse(
            container(0x424C4B35, sections),
            meta("{\"version\":\"v\",\"rules\":" + rulesJson + "}")));
  }

  @Test
  void unknownActionAndEmptyRulesAreDropped() {
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"a\",\"action\":\"teleport\",\"conds\":[{\"f\":\"path\",\"op\":\"is\",\"v\":\"/x\"}]},"
                + "{\"id\":\"b\",\"action\":\"block\",\"conds\":[]},"
                + "{\"id\":\"c\",\"action\":\"block\",\"conds\":[{\"f\":\"path\",\"op\":\"is\",\"v\":\"/x\"}]}]");
    assertEquals(List.of("c"), m.snap.rules().stream().map(Parser.CompiledRule::id).toList());
    assertEquals("c", m.match(MatchInput.ip(null).withPath("/x")).rule());
  }

  @Test
  void regexJavaRejectsNeverMatchesAndNeverRaises() {
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"bad\",\"action\":\"block\",\"conds\":[{\"f\":\"path\",\"op\":\"matches\",\"v\":\"(?<=a\"}]}]");
    assertFalse(m.match(MatchInput.ip(null).withPath("/a")).block());
    Matcher m2 =
        new Matcher(
            Parser.parse(
                container(0x424C4B35),
                meta("{\"version\":\"v\",\"pathsRegex\":[\"(?<=a\",\"^/dump$\"]}")));
    assertEquals("path", m2.match(MatchInput.ip(null).withPath("/dump")).reason());
  }

  @Test
  void asnConditionsCompareAsStringsAndUnanswerableFieldsNeverFire() {
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"asn\",\"action\":\"block\",\"conds\":[{\"f\":\"asn\",\"op\":\"is_in\",\"v\":[14061,\"7922\"]}]},"
                + "{\"id\":\"cc\",\"action\":\"block\",\"conds\":[{\"f\":\"country\",\"op\":\"is_not\",\"v\":\"US\"}]}]");
    assertEquals("asn", m.match(MatchInput.ip(null).withAsn(14061L)).rule());
    assertEquals("asn", m.match(MatchInput.ip(null).withAsn(7922L)).rule());
    assertNull(
        m.match(MatchInput.ip(null).withAsn(1L))
            .rule()); // country unanswerable: is_not stays false
    assertEquals("cc", m.match(MatchInput.ip(null).withCountry("BR")).rule());
  }

  @Test
  void headerGetterThatRaisesOrReturnsJunkReadsAsAbsent() {
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"h\",\"action\":\"block\",\"conds\":[{\"f\":\"header\",\"op\":\"is\",\"name\":\"X-Api-Key\",\"v\":\"k\"}]}]");
    assertFalse(
        m.match(
                MatchInput.ip(null)
                    .withHeader(
                        n -> {
                          throw new RuntimeException("app bug");
                        }))
            .block());
    assertFalse(
        m.match(MatchInput.ip(null).withHeader(n -> n.equals("x-api-key") ? "" : null)).block());
    assertEquals(
        "h",
        m.match(MatchInput.ip(null).withHeader(n -> n.equals("x-api-key") ? "k" : null)).rule());
  }

  @Test
  void twoIpConditionsConsumeTwoSectionPairsInOrder() {
    int a = (10 << 24) | 1;
    int b = (10 << 24) | 2;
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"r\",\"action\":\"block\",\"conds\":[{\"f\":\"ip\",\"op\":\"is_in\",\"set\":true},{\"f\":\"ip\",\"op\":\"not_in\",\"set\":true}]}]",
            new Section(14, 0, a, a),
            new Section(15, 0),
            new Section(14, 0, b, b),
            new Section(15, 0));
    assertEquals("r", m.match(MatchInput.ip("10.0.0.1")).rule()); // in the first, not in the second
    assertNull(m.match(MatchInput.ip("10.0.0.2")).rule()); // not in the first
  }

  @Test
  void jsRegexSpellingsAreTranslated() {
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"ver\",\"action\":\"block\",\"conds\":[{\"f\":\"path\",\"op\":\"matches\",\"v\":\"^/api/(?<ver>v\\\\d+)/\"}]}]");
    assertEquals("ver", m.match(MatchInput.ip(null).withPath("/api/v2/dump")).rule());
    assertNull(
        m.match(MatchInput.ip(null).withPath("/api/v٣/dump"))
            .rule()); // \d is ASCII, as JS reads it
    Matcher m2 =
        rulesSnapshot(
            "[{\"id\":\"any\",\"action\":\"block\",\"conds\":[{\"f\":\"ua\",\"op\":\"matches\",\"v\":\"^a[^]b$\"}]}]");
    assertEquals("any", m2.match(MatchInput.ip(null).withUa("a b")).rule()); // [^] is any char

    assertNull(m2.match(MatchInput.ip(null).withUa("ab")).rule());
    // JS's $ is the very end; Java's would also accept a trailing newline
    Matcher m3 =
        rulesSnapshot(
            "[{\"id\":\"end\",\"action\":\"block\",\"conds\":[{\"f\":\"ua\",\"op\":\"matches\",\"v\":\"^x$\"}]}]");
    assertEquals("end", m3.match(MatchInput.ip(null).withUa("x")).rule());
    assertEquals("end", m3.match(MatchInput.ip(null).withUa("x\n")).rule()); // \n is stripped first
    assertEquals("^a[\\s\\S]b\\x0A\\z", Parser.jsToJava("^a[^]b\\cJ$"));
    assertEquals("[$]\\$a(b)(?<=c)(?<!d)", Parser.jsToJava("[$]\\$a(?<n>b)(?<=c)(?<!d)"));
    assertEquals("a\\x0A", Parser.jsToJava("a\\cj")); // JS reads \cj as \cJ; Java would not
    // JS admits _ and $ in a group name; Java only letters and digits, so names are dropped and a
    // \k<name> back-reference becomes its number (nothing in the SDK reads the names)
    Matcher m4 =
        rulesSnapshot(
            "[{\"id\":\"u\",\"action\":\"block\",\"conds\":[{\"f\":\"path\",\"op\":\"matches\",\"v\":\"^/u/(?<user_id>\\\\d+)/(?<$x>[a-z]+)/\\\\k<user_id>0$\"}]}]");
    assertEquals("u", m4.match(MatchInput.ip(null).withPath("/u/7/a/70")).rule());
    assertNull(m4.match(MatchInput.ip(null).withPath("/u/7/a/80")).rule());
    assertNull(m4.match(MatchInput.ip(null).withPath("/u/7/a/7")).rule());
    assertEquals(
        "^(a)(?:x)(\\d)(?:\\2)\\k<m>[(?<n>]",
        Parser.jsToJava(
            "^(a)(?:x)(?<n>\\d)\\k<n>\\k<m>[(?<n>]")); // \k<m>: no such group, left alone
    assertNull(Parser.compileRegex("(?<user_id>a)\\k<nope>")); // an unknown name still fails open
    // a { that opens no valid quantifier is a literal in JS; Java would throw
    for (String[] c :
        new String[][] {
          {"a{}", "a{}"},
          {"/api/{id}", "/api/{id}"},
          {"x{,3", "x{,3"},
          {"[{,3}]", "{"},
          {"a{x}", "a{x}"},
          {"a{,}", "a{,}"},
          {"a{,3}", "a{,3}"}
        }) {
      Pattern p = Parser.compileRegex(c[0]);
      assertNotNull(p, c[0]);
      assertTrue(p.matcher(c[1]).matches(), c[0]);
      Pattern pi = Parser.compileRegex(c[0], Pattern.CASE_INSENSITIVE); // the path flags
      assertTrue(pi.matcher(c[1].toUpperCase(Locale.ROOT)).matches(), c[0]);
    }
    // non-ASCII case folding under /i, and an astral char in a class, as JS reads them
    assertTrue(Parser.compileRegex("^é$", Pattern.CASE_INSENSITIVE).matcher("É").matches());
    assertFalse(Parser.compileRegex("^é$").matcher("É").matches());
    // an astral class char stays one code point: JS's two-unit reading cannot be mirrored for
    // find()
    assertTrue(Parser.compileRegex("[😀]").matcher("x😀y").find());
    assertFalse(Parser.compileRegex("^[^😀]$").matcher("😀").find());
    assertTrue(Parser.compileRegex("^😀$").matcher("😀").matches());
    assertEquals("a\\{}", Parser.jsToJava("a{}"));
    assertEquals("x\\{,3", Parser.jsToJava("x{,3"));
    assertEquals("a\\{x}", Parser.jsToJava("a{x}"));
    assertEquals("a\\{,}", Parser.jsToJava("a{,}"));
    assertEquals("a\\{,3}", Parser.jsToJava("a{,3}"));
    // after a lookahead too: it compiles and, as in JS, never matches; a real {2} stays a
    // quantifier
    assertEquals("a(?=b)\\{x}", Parser.jsToJava("a(?=b){x}"));
    assertFalse(Parser.compileRegex("a(?=b){x}").matcher("ab{x}").find());
    assertFalse(Parser.compileRegex("a(?=b){x}", Pattern.CASE_INSENSITIVE).matcher("AB{X}").find());
    assertTrue(Parser.compileRegex("a(?=b){2}b").matcher("ab").matches());
    assertNull(Parser.compileRegex("a{2,1}")); // JS rejects it too
    Pattern q2 = Parser.compileRegex("^a{2}$");
    assertTrue(q2.matcher("aa").find());
    assertFalse(q2.matcher("a").find());
    assertTrue(Parser.compileRegex("^a{2,}$").matcher("aaaa").find());
    assertFalse(Parser.compileRegex("^a{2,}$").matcher("a").find());
    assertTrue(Parser.compileRegex("^a{2,3}$").matcher("aaa").find());
    assertFalse(Parser.compileRegex("^a{2,3}$").matcher("aaaa").find());
    Pattern huge = Parser.compileRegex("^a{1,99999999999}$");
    assertTrue(huge.matcher("a").find());
    assertEquals("a{2147483647,2147483647}b{3}", Parser.jsToJava("a{99999999999,99999999999}b{3}"));
    assertEquals("/api/\\{id}", Parser.jsToJava("/api/{id}"));
    assertEquals("a\\{b a{2,3} [{,3}]", Parser.jsToJava("a{b a{2,3} [{,3}]"));
    assertEquals("a\\{b[{]", Parser.jsToJava("a\\{b[{]"));
    // a [ or && inside a class is a literal in JS; Java reads a union / an intersection
    assertEquals("^[a\\[b]]\\z", Parser.jsToJava("^[a[b]]$"));
    assertEquals("[a\\&&b]", Parser.jsToJava("[a&&b]")); // one escaped & ends the intersection
    assertEquals("[\\&&]", Parser.jsToJava("[&&]"));
    // the vectors below match what node's new RegExp matches
    for (Object[] c :
        new Object[][] {
          {"^[a[b]]$", "a]", true},
          {"^[a[b]]$", "a", false},
          {"^[a[b]]$", "b]", true},
          {"^[a[b]]$", "[]", true},
          {"[a&&b]", "&", true},
          {"[a&&b]", "a", true},
          {"[a&&b]", "c", false},
          {"^[&&]$", "&", true},
          {"^[&&]$", "&&", false},
          {"^[a&b]$", "&", true}
        }) {
      Pattern p = Parser.compileRegex((String) c[0]);
      assertNotNull(p, (String) c[0]);
      assertEquals(c[2], p.matcher((String) c[1]).find(), c[0] + " vs " + c[1]);
    }
  }

  // pattern, input, whether JS's new RegExp(pattern).test(input) is true (checked with node)
  private static void js(String p, String in, boolean want) {
    Pattern c = Parser.compileRegex(p);
    assertNotNull(c, p);
    assertEquals(want, c.matcher(in).find(), p + " on " + in);
  }

  // same as js, but the way a CASE_INSENSITIVE (path) regex compiles; node: new RegExp(p, "i")
  private static void jsi(String p, String in, boolean want) {
    Pattern c = Parser.compileRegex(p, Pattern.CASE_INSENSITIVE);
    assertNotNull(c, p);
    assertEquals(want, c.matcher(in).find(), p + " on " + in);
  }

  @Test
  void jsIdentityEscapesAndEmptyClassReadAsJsReadsThem() {
    // JS escapes with no meaning stay as the bare letter; {41} is then a quantifier
    js("^\\x{41}$", "x".repeat(41), true);
    js("^\\x{41}$", "A", false);
    js("^\\u{41}$", "u".repeat(41), true);
    js("^\\u{41}$", "A", false);
    js("^\\x4G\\u004$", "x4Gu004", true);
    js("^\\p{L}$", "p{L}", true);
    js("^\\p{L}$", "a", false);
    js("^\\P{L}$", "P{L}", true);
    js("^\\N{x}$", "N{x}", true);
    js("^\\Q.\\E$", "QaE", true); // \Q..\E is not a quote in JS: the . stays live
    js("^\\Qa\\E$", "a", false);
    js("^\\a\\e\\h\\y\\z\\K\\X$", "aehyzKX", true);
    // \c with no letter is a literal backslash and c
    js("^\\c{2}$", "\\cc", true);
    js("^\\c{2}$", ";2", false);
    js("^\\c{x}$", "\\c{x}", true);
    js("^\\c{x}$", "\u0018", false);
    js("^\\c{x}$", "c{x}", false);
    js("^\\c1$", "\\c1", true);
    js("^a\\c$", "a\\c", true);
    js("^\\cé$", "\\cé", true);
    js("^\\cé$", "\u0089", false);
    assertEquals("\\\\c{2}", Parser.jsToJava("\\c{2}"));
    // inside a class \c also takes a digit or _
    js("^[\\c1]$", "\u0011", true);
    js("^[\\c1]$", "q", false);
    js("^[\\c_]$", "\u001f", true);
    js("^[\\c*]$", "\\", true);
    js("^[\\c*]$", "c", true);
    js("^[\\c*]$", "*", true);
    // \k is a back-reference only when the pattern has a named group
    js("^\\k<a>$", "k<a>", true);
    js("^\\k<a>$", "k", false);
    js("^[(?<n>]\\k$", "(k", true);
    js("^\\(?<n>\\k$", "(<n>k", true); // \( is a literal, so no group: \k is k
    js("^\\(?<n>\\k$", "(?<n>k", false);
    assertEquals("^\\(?<n>k\\z", Parser.jsToJava("^\\(?<n>\\k$"));
    // [] is an empty class: it never matches, and a quantifier on it still parses
    js("[]", "", false);
    js("[]", "a", false);
    js("^[]a]$", "a]", false);
    js("^a[]?b$", "ab", true);
    js("^a[]{2}b$", "ab", false);
    js("^[\\B\\p]+$", "Bp", true);
    js("^\\é-$", "é-", true);
    js("^\\d\\s\\w$", "1 a", true);
    // the escapes JS knows must pass through untouched
    String known = "\\d\\D\\w\\W\\f\\n\\r\\t";
    assertEquals(known, Parser.jsToJava(known));
    assertEquals("\\d{6}", Parser.jsToJava("\\d{6}"));
    // a path regex runs CASE_INSENSITIVE
    Pattern px = Parser.compileRegex("^\\X$", Pattern.CASE_INSENSITIVE);
    assertNotNull(px);
    assertTrue(px.matcher("x").find());
    Pattern pe = Parser.compileRegex("^[]$", Pattern.CASE_INSENSITIVE);
    assertNotNull(pe);
    assertFalse(pe.matcher("A").find());
  }

  @Test
  void jsVerticalTabNulBackspaceOctalAndForwardReferencesReadAsJsReadsThem() {
    // camada-all-wrqf
    js("^\\v$", "\n", false); // JS \v is only U+000B; Java's is all vertical whitespace
    js("^\\v$", "\u000B", true);
    js("^[\\v]$", "\n", false);
    js("^\\0$", "\u0000", true);
    js("^\\08$", "\u00008", true);
    js("^[\\0]$", "\u0000", true);
    js("^[\\b]$", "\b", true); // in a class \b is backspace
    js("^[\\b]$", "b", false);
    // legacy octal and \8 \9 when the number is not a group
    js("^\\1$", "\u0001", true); // no groups: legacy octal
    js("^\\8$", "8", true);
    js("^\\81$", "81", true);
    js("^\\18$", "\u00018", true);
    js("^\\377$", "\u00FF", true);
    js("^\\400$", " 0", true);
    js("^(a)\\10$", "a\b", true);
    js("^(a)\\10$", "aa0", false);
    js("^(a)[\\1]$", "a\u0001", true); // no back-references inside a class
    js("^[\\8]$", "8", true);
    js("^(?<a>x)\\2$", "x\u0002", true);
    // back-references that exist stay back-references
    js("^(a)\\1$", "aa", true);
    js("^(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\\10$", "abcdefghijj", true);
    js("^(?<a>x)\\k<a>$", "xx", true);
    // forward or open references match empty
    js("^(?:\\1(a))$", "a", true); // forward reference matches empty
    js("^\\2(a)(b)$", "ab", true);
    js("^(a\\1)$", "a", true);
    js("^\\k<a>(?<a>x)$", "x", true);
    js("^(?<a>x\\k<a>)$", "x", true);
    assertEquals("(a)(?:\\1)", Parser.jsToJava("(a)\\1"));
    assertEquals("\\x200", Parser.jsToJava("\\400"));
  }

  @Test
  void jsSpaceAndWordBoundaryReadAsJsReadsThem() {
    // camada-all-ooqj: Java's \s is ASCII-only and its \b counts non-ASCII letters as word chars
    js("union\\s+select", "union\u00A0select", true);
    js("^\\S$", "\u00A0", false);
    js("^\\s$", " ", true);
    js("^\\s$", "\uFEFF", true);
    js("^\\s$", "\u180E", false);
    js("^\\s$", "\u0085", false);
    js("^[\\s-z]+$", "-z ", true);
    js("^[\\s-z]$", "y", false);
    js("^[a-\\s]+$", "a- ", true);
    js("^[^\\S]$", " ", true);
    js("^[^a\\S]$", "\u00A0", true);
    js("^[^a\\S]$", "b", false);
    js("^[\\S]$", " ", false);
    js("^[^]$", " ", true);
    js("^\\s$", "\u2028", true);
    js("^\\S$", "\u2028", false);
    js("^[\\S]$", "\u2028", false);
    js("^[^]$", "\u2028", true);
    js("a\\b", "aé", true);
    js("a\\B", "aé", false);
    js("\\bé", "é", false);
    js("\\Bé", "é", true);
    // CASE_INSENSITIVE, the way a path regex compiles
    jsi("\\bunion\\s+select", "UNION\u00A0SELECT", true);
    jsi("^\\S$", "\u00A0", false);
    jsi("^[^\\s]$", "\uFEFF", false);
    jsi("^a\\b", "A\u212A", true); // K is U+212A (Kelvin sign): JS /i keeps it a non-word char
    jsi("^a\\B", "A\u212A", false);
    jsi("^k\\b", "k\u017F", true); // U+017F long s is not a word char either
    // every BMP char: \s is exactly JS's set (node, looping 0..0xFFFF), \S its complement
    String jsSpace =
        "\t\n\u000B\f\r \u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
            + "\u2009\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF";
    Pattern s = Parser.compileRegex("^\\s$");
    Pattern ns = Parser.compileRegex("^[^\\S]$", Pattern.CASE_INSENSITIVE);
    for (char c = 0; c < 0xFFFF; c++) {
      if (!Character.isSurrogate(c)) {
        String in = String.valueOf(c);
        boolean want = jsSpace.indexOf(c) >= 0;
        assertEquals(want, s.matcher(in).find(), "\\s on U+" + Integer.toHexString(c));
        assertEquals(want, ns.matcher(in).find(), "[^\\S] on U+" + Integer.toHexString(c));
      }
    }
    assertEquals("(?:(?<=\\w)(?!\\w)|(?<!\\w)(?=\\w))", Parser.jsToJava("\\b"));
  }

  private static String rule(String id, String action, String f, String name, String rx) {
    return "{\"id\":\""
        + id
        + "\",\"action\":\""
        + action
        + "\",\"conds\":[{\"f\":\""
        + f
        + "\",\"op\":\"matches\","
        + (name == null ? "" : "\"name\":\"" + name + "\",")
        + "\"v\":\""
        + rx.replace("\\", "\\\\")
        + "\"}]}";
  }

  @Test
  void matchesCapsInputAtMaxFailingClosedForDenyAndMissForSkip() {
    Matcher deny =
        rulesSnapshot(
            "["
                + rule("u", "warn", "ua", null, "(Scrapy|python-requests)/[0-9]")
                + ","
                + rule("h", "challenge", "header", "x-v", "^1\\.[0-2]\\.")
                + ","
                + rule("p", "block", "path", null, "^/api/v[0-9]+/dump$")
                + "]");
    String a2047 = "a".repeat(Parser.MAX_MATCH_INPUT);
    assertNull(deny.match(MatchInput.ip(null).withUa(a2047)).rule());
    assertEquals("u", deny.match(MatchInput.ip(null).withUa(a2047 + "a")).rule());
    assertNull(deny.match(MatchInput.ip(null).withUa("\u00e9".repeat(2048))).rule());
    assertNull(deny.match(MatchInput.ip(null).withUa("\ud83d\ude00".repeat(1024))).rule());
    assertEquals("u", deny.match(MatchInput.ip(null).withUa("\ud83d\ude00".repeat(1025))).rule());
    assertEquals("h", deny.match(MatchInput.ip(null).withHeader(n -> "9".repeat(2049))).rule());
    assertNull(deny.match(MatchInput.ip(null).withHeader(n -> "9".repeat(2048))).rule());
    assertNull(deny.match(MatchInput.ip(null).withPath("/x/" + "a".repeat(2045))).rule());
    assertEquals("p", deny.match(MatchInput.ip(null).withPath("/x/" + "a".repeat(2046))).rule());
    assertEquals("p", deny.match(MatchInput.ip(null).withPath("/" + "%61".repeat(700))).rule());
    assertNull(deny.match(MatchInput.ip(null).withPath("/x?" + "q".repeat(3000))).rule());
    // camada-all-wh9m: a deny rule also reads the raw value, so 2048 + a TAB (raw 2049) is over the
    // cap and hits (v2 pinned a miss here)
    assertEquals(
        "u",
        deny.match(MatchInput.ip(null).withUa("Mozilla/5.0 " + "a".repeat(2036) + "\t")).rule());

    Matcher skip =
        rulesSnapshot(
            "["
                + rule("s", "skip", "ua", null, "^uptime-probe/[0-9]")
                + ","
                + rule("sp", "skip", "path", null, "^/static-mirror/")
                + ","
                + rule("e", "warn", "ua", null, "Scrapy")
                + ","
                + rule("c", "block", "path", null, "^/api/v[0-9]+/dump$")
                + "]");
    String up = "uptime-probe/1 ";
    assertEquals("s", skip.match(MatchInput.ip(null).withUa(up + "a".repeat(2033))).rule());
    assertEquals("e", skip.match(MatchInput.ip(null).withUa(up + "a".repeat(2034))).rule());
    String sm = "/static-mirror/";
    assertEquals("sp", skip.match(MatchInput.ip(null).withPath(sm + "a".repeat(2033))).rule());
    assertEquals("c", skip.match(MatchInput.ip(null).withPath(sm + "a".repeat(2034))).rule());
    assertEquals("sp", skip.match(MatchInput.ip(null).withPath(sm + "%61".repeat(700))).rule());
    assertEquals(
        "c", skip.match(MatchInput.ip(null).withPath(sm + "./".repeat(1100) + "x")).rule());
  }

  @Test
  void anEngineFailureUnderTheCapFailsClosedForDenyAndMissForSkip() throws Exception {
    // java.util.regex recurses per iteration: a 2000-char value under the cap overflows a small
    // stack
    String ua = "a".repeat(2000) + "b";
    String deepRx = "^(?:a|b)*c";
    boolean[] overflowed = {false};
    String[] got = new String[3];
    Thread t =
        new Thread(
            null,
            () -> {
              try {
                java.util.regex.Pattern.compile(deepRx).matcher(ua).find();
              } catch (StackOverflowError e) {
                overflowed[0] = true;
              }
              Matcher deny = rulesSnapshot("[" + rule("d", "block", "ua", null, deepRx) + "]");
              got[0] = deny.match(MatchInput.ip(null).withUa(ua)).rule();
              Matcher skip =
                  rulesSnapshot(
                      "["
                          + rule("s", "skip", "ua", null, deepRx)
                          + ","
                          + rule("e", "warn", "ua", null, "^a")
                          + "]");
              got[1] = skip.match(MatchInput.ip(null).withUa(ua)).rule();
              Matcher path =
                  rulesSnapshot("[" + rule("p", "block", "path", null, "^/(?:a|b)*c") + "]");
              got[2] = path.match(MatchInput.ip(null).withPath("/" + ua)).rule();
            },
            "tiny-stack",
            64 * 1024);
    t.start();
    t.join();
    assertTrue(overflowed[0], "the engine must fail for this test to mean anything");
    assertEquals("d", got[0]);
    assertEquals("e", got[1]);
    assertEquals("p", got[2]);
  }

  @Test
  void controlCharsAreStrippedFromUaAndHeaderForMatchesOnly() {
    Matcher m =
        rulesSnapshot(
            "["
                + rule("e", "warn", "ua", null, "(Scrapy|python-requests)/[0-9]")
                + ","
                + rule("s", "skip", "header", "x-p", "^partner-[a-z]+$")
                + ","
                + "{\"id\":\"k\",\"action\":\"block\",\"conds\":[{\"f\":\"ua\",\"op\":\"contains\",\"v\":\"curl/\"}]},"
                + rule("c", "block", "path", null, "^/api/v[0-9]+/dump$")
                + "]");
    assertEquals("e", m.match(MatchInput.ip(null).withUa("python-requests\u0000/2.32.0")).rule());
    assertEquals("e", m.match(MatchInput.ip(null).withUa("Scrapy\t/2.11")).rule());
    assertEquals("e", m.match(MatchInput.ip(null).withUa("python-requests/\u007f2")).rule());
    assertNull(m.match(MatchInput.ip(null).withUa("cu\u0000rl/8.4.0")).rule());
    // a skip never exempts a value that carries a control char (v2 pinned "s")
    assertNull(m.match(MatchInput.ip(null).withHeader(n -> "partner-acme\n")).rule());
    assertEquals("s", m.match(MatchInput.ip(null).withHeader(n -> "partner-acme")).rule());
    assertNull(m.match(MatchInput.ip(null).withPath("/api/v2/dump\n")).rule());
    assertNull(m.match(MatchInput.ip(null).withPath("/api/v2/dump%0A")).rule());
    assertEquals("c", m.match(MatchInput.ip(null).withPath("/api/v2/dump")).rule());
  }

  @Test
  void aDenyReadsRawAndStrippedAndASkipNeverTakesAControlChar() {
    Matcher m =
        rulesSnapshot(
            "["
                + rule("t", "block", "ua", null, "a\\tb")
                + ","
                + rule("q", "block", "ua", null, "sqlmap")
                + ","
                + rule("ht", "block", "header", "x-h", "a\\tb")
                + ","
                + rule("hq", "block", "header", "x-q", "sqlmap")
                + "]");
    assertEquals("t", m.match(MatchInput.ip(null).withUa("a\tb")).rule());
    assertEquals("q", m.match(MatchInput.ip(null).withUa("sql\tmap")).rule());
    assertNull(m.match(MatchInput.ip(null).withUa("ab")).rule());
    assertEquals(
        "ht", m.match(MatchInput.ip(null).withHeader(n -> n.equals("x-h") ? "a\tb" : null)).rule());
    assertEquals(
        "hq",
        m.match(MatchInput.ip(null).withHeader(n -> n.equals("x-q") ? "sql\tmap" : null)).rule());
    Matcher s =
        rulesSnapshot(
            "["
                + rule("s", "skip", "ua", null, "^partner-[a-z]+$")
                + ","
                + rule("d", "block", "ua", null, "partner")
                + "]");
    assertEquals("s", s.match(MatchInput.ip(null).withUa("partner-acme")).rule());
    assertEquals("d", s.match(MatchInput.ip(null).withUa("partner-acme\n")).rule());
    // raw over the cap, stripped under it: deny hits, skip misses
    Matcher o =
        rulesSnapshot(
            "["
                + rule("s", "skip", "ua", null, "^a+$")
                + ","
                + rule("d", "block", "ua", null, "^zzz$")
                + "]");
    String big = "a".repeat(Parser.MAX_MATCH_INPUT) + "\t";
    assertEquals("d", o.match(MatchInput.ip(null).withUa(big)).rule());
    assertEquals(
        "s", o.match(MatchInput.ip(null).withUa("a".repeat(Parser.MAX_MATCH_INPUT))).rule());
  }

  @Test
  void oneMatcherServesConcurrentRequestsWithoutCrosstalk() throws InterruptedException {
    int a = (10 << 24) | 1;
    Matcher m =
        rulesSnapshot(
            "[{\"id\":\"r\",\"action\":\"block\",\"conds\":[{\"f\":\"header\",\"op\":\"is\",\"name\":\"x-a\",\"v\":\"1\"},{\"f\":\"ip\",\"op\":\"is_in\",\"set\":true}]}]",
            new Section(14, 0, a, a),
            new Section(15, 0));
    java.util.function.Function<String, String> header =
        n -> {
          Thread.yield(); // hand the CPU to the other request between the header read and the ip
          // check
          return "1";
        };
    int[] wrong = new int[2];
    Runnable hammer0 =
        () -> {
          for (int k = 0; k < 1500; k++) {
            if (!m.match(MatchInput.ip("10.0.0.1").withHeader(header)).block()) {
              wrong[0]++;
            }
          }
        };
    Runnable hammer1 =
        () -> {
          for (int k = 0; k < 1500; k++) {
            if (m.match(MatchInput.ip("10.0.0.2").withHeader(header)).block()) {
              wrong[1]++;
            }
          }
        };
    Thread t0 = new Thread(hammer0);
    Thread t1 = new Thread(hammer1);
    t0.start();
    t1.start();
    t0.join();
    t1.join();
    assertEquals(0, wrong[0]);
    assertEquals(0, wrong[1]);
  }
}
