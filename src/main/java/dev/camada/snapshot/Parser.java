package dev.camada.snapshot;

import dev.camada.Config;
import dev.camada.Json;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * BLK snapshot parser (v3, v4, v5), ported from {@code @camada/core} src/snapshot/parse.ts, itself
 * a port of edge-analyst src/blocklist.js load() (the reference implementation).
 *
 * <p>Container: sectioned little-endian uint32 — [0] magic 0x424c4b3&lt;version&gt; [1] section
 * count K, K x [type, offset(words), length(words)], then the sections. Types: 1 V4_STARTS 2
 * V4_ENDS 3 V4_IDX16 4 V4_BM24 5 V6_STARTS 6 V6_ENDS 7 V6_BM24 8 ASN_BM 9 ASN_EXTRA. v4 (contracts
 * §A3) adds two side lists as INTERLEAVED range pairs: 10 ALLOW_V4 11 ALLOW_V6 12 CHALLENGE_V4 13
 * CHALLENGE_V6 — *_V4: [start, end, …] (2 words per range, sorted by start); *_V6: [s0,s1,s2,s3,
 * e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start). v5 (contracts §D3)
 * adds the tenant's ordered custom rules, which run BEFORE the three sides: 14 RULE_V4 15 RULE_V6 —
 * repeated, word 0 = the rule's index into meta.rules, then range pairs exactly as 10/11. One 14 +
 * one 15 per {@code ip} condition, in condition order (an empty half still ships its index word),
 * so a rule with two ip conditions reads two pairs. Meta travels separately: { version, country[],
 * tls[], pathsExact[], pathsPrefix[], pathsRegex[], allow?: side, challenge?: side, rules?: [] }
 * with side = { asn[], country[], pathsExact[], pathsPrefix[] }. The version byte is advisory:
 * sections 10-15 are read whenever they are present.
 *
 * <p>A Uint32Array is an {@link IntBuffer} view over the little-endian bytes: zero-copy, read with
 * absolute gets only (so one parsed snapshot serves every thread), compared unsigned.
 */
public final class Parser {
  private Parser() {}

  private static final Map<Integer, Integer> FORMATS =
      Map.of(0x424C4B33, 3, 0x424C4B34, 4, 0x424C4B35, 5);
  private static final IntBuffer EMPTY = IntBuffer.allocate(0);
  private static final Set<String> ACTIONS = Set.of("skip", "block", "challenge", "warn");

  /** A v4 side list. {@code empty} short-circuits the matcher on the (common) v3 snapshot. */
  public record RangeSet(
      IntBuffer r4,
      IntBuffer r6,
      int n6,
      Set<Long> asn,
      Set<String> country,
      Set<String> pathsExact,
      Set<String> pathsPrefix,
      boolean empty) {}

  /** The request a compiled condition reads. {@code ip6} is the parsed address words, or null. */
  public static final class RuleRequest {
    long n4 = -1; // IPv4 as uint32, or -1 when this request has no IPv4 address
    int[] ip6;
    Long asn;
    String country;
    String tlsx;
    String path = "/"; // already query-stripped
    String ua;
    Function<String, String>
        header; // called with an already lower-cased name; null where the tap cannot read headers
  }

  /** One compiled condition. */
  @FunctionalInterface
  public interface RuleCond {
    boolean test(RuleRequest r);
  }

  public record CompiledRule(String id, String action, List<RuleCond> conds) {}

  public record Snapshot(
      String version,
      int format, // what the container's version byte claimed
      IntBuffer s4,
      IntBuffer e4,
      IntBuffer idx4,
      IntBuffer bm4,
      IntBuffer s6,
      IntBuffer e6,
      int n6,
      IntBuffer bm6,
      IntBuffer asnBm,
      IntBuffer asnExtra,
      Set<String> country,
      Set<String> tls,
      Set<String> pathsExact,
      Set<String> pathsPrefix,
      List<Pattern> pathsRegex,
      RangeSet allow,
      RangeSet challenge,
      List<CompiledRule> rules) {} // v5 only; empty on v3/v4, and the matcher then skips them

  private static IntBuffer words(ByteBuffer binary) {
    // a trailing partial word is dropped, as the Uint32Array view does
    return binary.slice().order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
  }

  private static IntBuffer slice(IntBuffer u, int off, int len) {
    IntBuffer d = u.duplicate();
    d.position(off);
    d.limit(off + len);
    return d.slice();
  }

  private static Set<String> strings(Object v) {
    return new HashSet<>(dev.camada.Config.strings(v));
  }

  private static Set<Long> longs(Object v) {
    Set<Long> out = new HashSet<>();
    if (v instanceof List<?> l) {
      for (Object o : l) {
        if (o instanceof Number n) {
          out.add(n.longValue());
        } else if (o instanceof String s) {
          try {
            out.add(Long.parseLong(s.trim()));
          } catch (NumberFormatException e) {
            // not an ASN: skipped, as int() would raise in the reference
          }
        }
      }
    }
    return out;
  }

  private static RangeSet rangeSet(IntBuffer r4, IntBuffer r6, Map<String, Object> m) {
    Set<Long> asn = m == null ? Set.of() : longs(m.get("asn"));
    Set<String> country = m == null ? Set.of() : strings(m.get("country"));
    Set<String> exact = m == null ? Set.of() : strings(m.get("pathsExact"));
    Set<String> prefix = m == null ? Set.of() : strings(m.get("pathsPrefix"));
    boolean empty =
        r4.limit() == 0
            && r6.limit() == 0
            && asn.isEmpty()
            && country.isEmpty()
            && exact.isEmpty()
            && prefix.isEmpty();
    return new RangeSet(r4, r6, r6.limit() >> 3, asn, country, exact, prefix, empty);
  }

  /** Binary search over interleaved [start, end] uint32 pairs sorted by start. */
  static boolean inRange4(IntBuffer r, int n) {
    int lo = 0;
    int hi = (r.limit() >> 1) - 1;
    if (hi < 0) {
      return false;
    }
    while (lo < hi) {
      int m = (lo + hi + 1) >>> 1;
      if (Integer.compareUnsigned(r.get(m * 2), n) <= 0) {
        lo = m;
      } else {
        hi = m - 1;
      }
    }
    return Integer.compareUnsigned(r.get(lo * 2), n) <= 0
        && Integer.compareUnsigned(n, r.get(lo * 2 + 1)) <= 0;
  }

  /** Compares the 4 words at a[o..o+3] against the address words. */
  static int cmpWords(IntBuffer a, int o, int[] w) {
    for (int k = 0; k < 4; k++) {
      int c = Integer.compareUnsigned(a.get(o + k), w[k]);
      if (c != 0) {
        return c;
      }
    }
    return 0;
  }

  /** Binary search over an interleaved [4-word start, 4-word end] side section. */
  static boolean inRange6(IntBuffer r, int n, int[] w) {
    if (n < 1) {
      return false;
    }
    int lo = 0;
    int hi = n - 1;
    while (lo < hi) {
      int m = (lo + hi + 1) >>> 1;
      if (cmpWords(r, m * 8, w) <= 0) {
        lo = m;
      } else {
        hi = m - 1;
      }
    }
    int o = lo * 8;
    return cmpWords(r, o, w) <= 0 && cmpWords(r, o + 4, w) >= 0;
  }

  /**
   * A pattern this runtime cannot run against this input never matches, and never throws:
   * java.util.regex recurses per group iteration, so a nested quantifier against a long path or
   * user agent overflows the request thread's stack where JS and Python's engines would not.
   */
  public static boolean find(Pattern rx, String input) {
    try {
      return rx.matcher(input).find();
    } catch (StackOverflowError e) {
      return false;
    }
  }

  /**
   * A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
   * authored as JS regexes (the analyst validates them with {@code new RegExp}), so the JS
   * spellings java.util.regex reads differently are translated first — see {@link #jsToJava} — and
   * the default (non-UNICODE_CHARACTER_CLASS) mode keeps \d \w \b as JS reads them.
   */
  public static Pattern compileRegex(String pattern) {
    try {
      return Pattern.compile(jsToJava(pattern));
    } catch (RuntimeException | StackOverflowError e) {
      return null;
    }
  }

  /**
   * The JS spellings a tenant is likely to author and Java reads differently: {@code [^]} (any
   * char) -> {@code [\s\S]}, {@code \cX} -> the control character (Java's own \c reads a lower-case
   * letter differently), a bare {@code $} -> {@code \z} (Java's $ also accepts a final newline;
   * JS's does not), and a named group {@code (?<name>} -> a plain {@code (} with {@code \k<name>}
   * -> its number (JS admits {@code _} and {@code $} in a name, Java only letters and digits;
   * nothing in the SDK reads the names). Anything else the engine rejects still fails open.
   */
  static String jsToJava(String pattern) {
    StringBuilder out = new StringBuilder(pattern.length() + 8);
    int n = pattern.length();
    boolean inClass = false;
    int groups = 0; // capturing groups so far: what a \k<name> back-reference becomes
    Map<String, Integer> named = new HashMap<>();
    int i = 0;
    while (i < n) {
      char ch = pattern.charAt(i);
      if (ch == '\\' && i + 1 < n) {
        char nxt = pattern.charAt(i + 1);
        if (nxt == 'c' && i + 2 < n && Character.isLetter(pattern.charAt(i + 2))) {
          int code = Character.toUpperCase(pattern.charAt(i + 2)) - 64;
          out.append(String.format("\\x%02X", code));
          i += 3;
          continue;
        }
        if (nxt == 'k' && !inClass && i + 2 < n && pattern.charAt(i + 2) == '<') {
          int close = pattern.indexOf('>', i + 3);
          Integer num = close < 0 ? null : named.get(pattern.substring(i + 3, close));
          if (num != null) {
            out.append("(?:\\").append(num).append(')'); // grouped: a digit may follow
            i = close + 1;
            continue;
          }
        }
        out.append(ch).append(nxt);
        i += 2;
        continue;
      }
      if (inClass) {
        inClass = ch != ']';
      } else if (ch == '[') {
        if (pattern.startsWith("[^]", i)) {
          out.append("[\\s\\S]");
          i += 3;
          continue;
        }
        inClass = true;
      } else if (ch == '$') {
        out.append("\\z");
        i++;
        continue;
      } else if (ch == '(') {
        if (i + 1 >= n || pattern.charAt(i + 1) != '?') {
          groups++;
        } else if (i + 2 < n
            && pattern.charAt(i + 2) == '<'
            && i + 3 < n
            && pattern.charAt(i + 3) != '='
            && pattern.charAt(i + 3) != '!') {
          int close = pattern.indexOf('>', i + 3);
          if (close > 0) {
            named.put(pattern.substring(i + 3, close), ++groups);
            out.append('(');
            i = close + 1;
            continue;
          }
        }
      }
      out.append(ch);
      i++;
    }
    return out.toString();
  }

  // ---------- custom rules (v5) ----------

  /**
   * The string one condition reads, or null when this request cannot answer the field. {@code
   * header} is not here: it needs the condition's own name, so compileCond builds its reader.
   */
  private static String fieldValue(String f, RuleRequest r) {
    switch (f) {
      case "asn":
        return r.asn == null ? null : String.valueOf(r.asn);
      case "country":
        return r.country == null || r.country.isEmpty() ? null : r.country;
      case "tlsx":
        return r.tlsx == null || r.tlsx.isEmpty() ? null : r.tlsx;
      case "path":
        return r.path;
      case "ua":
        return r.ua == null || r.ua.isEmpty() ? null : r.ua;
      default:
        return null; // an entity-plane field (bot.verified, rule): never true here
    }
  }

  /** A section pair for one ip condition. */
  private record Pair(IntBuffer p4, IntBuffer p6) {}

  /**
   * One condition -> a predicate. {@code sets} yields this rule's (v4, v6) section pair per ip
   * condition, in condition order, so an ip condition consumes the next one.
   */
  private static RuleCond compileCond(Map<String, Object> c, List<Pair> sets) {
    String f = String.valueOf(c.getOrDefault("f", ""));
    String op = String.valueOf(c.getOrDefault("op", ""));
    boolean negate = op.equals("is_not") || op.equals("not_in");
    // A header condition reads the request through the caller's getter. The name is lower-cased
    // once, here; a tap that cannot read headers (no getter) and a header the request does not
    // carry are both null, and null is false for every op — the rule simply does not fire (fail
    // open, §A4). The getter is app code: one that throws, or answers something other than a
    // string, is read as "no header" rather than allowed to take the whole match() down.
    Function<RuleRequest, String> read;
    if (f.equals("header")) {
      Object name = c.get("name");
      String hname = name == null ? "" : String.valueOf(name).toLowerCase(Locale.ROOT);
      read =
          r -> {
            if (hname.isEmpty() || r.header == null) {
              return null;
            }
            try {
              return r.header.apply(hname);
            } catch (RuntimeException e) {
              return null;
            }
          };
    } else {
      read = r -> fieldValue(f, r);
    }

    if (f.equals("ip")) {
      Pair p = sets.isEmpty() ? new Pair(EMPTY, EMPTY) : sets.remove(0);
      IntBuffer p4 = p.p4();
      IntBuffer p6 = p.p6();
      int n6 = p6.limit() >> 3;
      return r -> {
        if (r.n4 < 0 && r.ip6 == null) {
          return false; // no address: false for every op, negatives included
        }
        boolean hit =
            (r.n4 >= 0 && inRange4(p4, (int) r.n4)) || (r.ip6 != null && inRange6(p6, n6, r.ip6));
        return negate != hit;
      };
    }
    Object raw = c.get("v");
    List<String> values = new ArrayList<>();
    if (raw instanceof List<?> l) {
      for (Object x : l) {
        values.add(jsString(x));
      }
    } else {
      values.add(jsString(raw));
    }
    String first = values.isEmpty() ? "" : values.get(0);
    switch (op) {
      case "matches":
        Pattern rx = compileRegex(first);
        return r -> {
          String v = read.apply(r);
          return v != null && rx != null && find(rx, v);
        };
      case "contains":
        return r -> {
          String v = read.apply(r);
          return v != null && v.contains(first);
        };
      case "starts_with":
        return r -> {
          String v = read.apply(r);
          return v != null && v.startsWith(first);
        };
      default: // is | is_not | is_in | not_in
        Set<String> members = new HashSet<>(values);
        return r -> {
          String v = read.apply(r);
          if (v == null) {
            return false;
          }
          return negate != members.contains(v);
        };
    }
  }

  /** {@code str(x)} as JS would spell a condition value: 14061 stays "14061", never "14061.0". */
  private static String jsString(Object x) {
    if (x instanceof Double d && d == Math.rint(d) && !d.isInfinite()) {
      return String.valueOf(d.longValue());
    }
    return String.valueOf(x);
  }

  /**
   * meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
   * cannot compile (unknown action, no conditions) is dropped rather than guessed at.
   */
  private static List<CompiledRule> compileRules(
      Map<String, Object> meta, List<IntBuffer> v4s, List<IntBuffer> v6s) {
    List<CompiledRule> out = new ArrayList<>();
    if (!(meta.get("rules") instanceof List<?> rules)) {
      return out;
    }
    for (int i = 0; i < rules.size(); i++) {
      Map<String, Object> r = Json.asMap(rules.get(i));
      if (r == null) {
        continue;
      }
      String action = String.valueOf(r.getOrDefault("action", ""));
      if (!ACTIONS.contains(action)) {
        continue; // an action this SDK does not know: ignore the rule rather than guess
      }
      List<IntBuffer> v4 = new ArrayList<>();
      for (IntBuffer s : v4s) {
        if (s.limit() > 0 && s.get(0) == i) {
          v4.add(s);
        }
      }
      List<IntBuffer> v6 = new ArrayList<>();
      for (IntBuffer s : v6s) {
        if (s.limit() > 0 && s.get(0) == i) {
          v6.add(s);
        }
      }
      List<Pair> sets = new ArrayList<>();
      for (int k = 0; k < Math.max(v4.size(), v6.size()); k++) {
        IntBuffer p4 = k < v4.size() ? slice(v4.get(k), 1, v4.get(k).limit() - 1) : EMPTY;
        IntBuffer p6 = k < v6.size() ? slice(v6.get(k), 1, v6.get(k).limit() - 1) : EMPTY;
        sets.add(new Pair(p4, p6));
      }
      List<RuleCond> conds = new ArrayList<>();
      try {
        if (r.get("conds") instanceof List<?> cl) {
          for (Object c : cl) {
            Map<String, Object> cm = Json.asMap(c);
            if (cm == null) {
              throw new IllegalArgumentException("malformed condition");
            }
            conds.add(compileCond(cm, sets));
          }
        }
      } catch (RuntimeException e) {
        continue; // a malformed rule is dropped, never enforced
      }
      if (!conds.isEmpty()) { // a rule with no conditions would match everything
        out.add(
            new CompiledRule(String.valueOf(r.getOrDefault("id", "")), action, List.copyOf(conds)));
      }
    }
    return out;
  }

  public static Snapshot parse(byte[] binary, Map<String, Object> meta) {
    return parse(ByteBuffer.wrap(binary), meta);
  }

  /**
   * Parses a BLK container + meta into a Snapshot. Throws IllegalArgumentException on a malformed
   * container — callers keep the previous snapshot, exactly like the edge collector does.
   */
  public static Snapshot parse(ByteBuffer binary, Map<String, Object> meta) {
    IntBuffer u = words(binary);
    Integer fmt = u.limit() >= 2 ? FORMATS.get(u.get(0)) : null;
    if (fmt == null) {
      throw new IllegalArgumentException("camada: not a BLK3 snapshot");
    }
    int count = u.get(1);
    if (count < 0 || u.limit() < 2 + (long) count * 3) {
      throw new IllegalArgumentException("camada: truncated BLK3 header");
    }
    Map<Integer, IntBuffer> sec = new HashMap<>();
    List<IntBuffer> rule4 = new ArrayList<>();
    List<IntBuffer> rule6 = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      int t = u.get(2 + i * 3);
      long off = Integer.toUnsignedLong(u.get(3 + i * 3));
      long ln = Integer.toUnsignedLong(u.get(4 + i * 3));
      if (off + ln > u.limit()) {
        throw new IllegalArgumentException("camada: truncated BLK3 section");
      }
      IntBuffer s = slice(u, (int) off, (int) ln);
      if (t == 14) {
        rule4.add(s); // repeated, one per ip condition: kept in container order
      } else if (t == 15) {
        rule6.add(s);
      } else {
        sec.put(t, s);
      }
    }
    IntBuffer s6 = sec.getOrDefault(5, EMPTY);
    List<Pattern> regex = new ArrayList<>();
    for (String p : Config.strings(meta.get("pathsRegex"))) {
      Pattern rx = compileRegex(p);
      if (rx != null) {
        regex.add(rx);
      }
    }
    return new Snapshot(
        String.valueOf(meta.getOrDefault("version", "")),
        fmt,
        sec.getOrDefault(1, EMPTY),
        sec.getOrDefault(2, EMPTY),
        sec.getOrDefault(3, IntBuffer.allocate(65537)),
        sec.getOrDefault(4, IntBuffer.allocate(524288)),
        s6,
        sec.getOrDefault(6, EMPTY),
        s6.limit() / 4,
        sec.getOrDefault(7, IntBuffer.allocate(524288)),
        sec.getOrDefault(8, IntBuffer.allocate(131072)),
        sec.getOrDefault(9, EMPTY),
        strings(meta.get("country")),
        strings(meta.get("tls")),
        strings(meta.get("pathsExact")),
        strings(meta.get("pathsPrefix")),
        List.copyOf(regex),
        rangeSet(
            sec.getOrDefault(10, EMPTY),
            sec.getOrDefault(11, EMPTY),
            Json.asMap(meta.get("allow"))),
        rangeSet(
            sec.getOrDefault(12, EMPTY),
            sec.getOrDefault(13, EMPTY),
            Json.asMap(meta.get("challenge"))),
        compileRules(meta, rule4, rule6));
  }
}
