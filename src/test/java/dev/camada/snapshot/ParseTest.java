package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.Map;
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
            "[{\"id\":\"any\",\"action\":\"block\",\"conds\":[{\"f\":\"ua\",\"op\":\"matches\",\"v\":\"^a[^]b\\\\cJ$\"}]}]");
    assertEquals("any", m2.match(MatchInput.ip(null).withUa("a\nb\n")).rule());
    assertNull(m2.match(MatchInput.ip(null).withUa("ab")).rule());
    // JS's $ is the very end; Java's would also accept a trailing newline
    Matcher m3 =
        rulesSnapshot(
            "[{\"id\":\"end\",\"action\":\"block\",\"conds\":[{\"f\":\"ua\",\"op\":\"matches\",\"v\":\"^x$\"}]}]");
    assertEquals("end", m3.match(MatchInput.ip(null).withUa("x")).rule());
    assertNull(m3.match(MatchInput.ip(null).withUa("x\n")).rule());
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
