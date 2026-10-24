package dev.camada.snapshot;

import dev.camada.Config;
import dev.camada.Guarded;
import dev.camada.Json;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
    String[] paths = {"/", "/", "/"}; // [raw, lit, full]: see Paths
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

  /** Exact path entries, canonicalised once at load (contracts §D3 "Path matching"). */
  private static Set<String> exactPaths(Object v) {
    Set<String> out = new HashSet<>();
    for (String p : dev.camada.Config.strings(v)) {
      out.add(Paths.canonPath(p));
    }
    return out;
  }

  /** Prefix entries -> their canonical directory keys ('/' stays '/', which covers everything). */
  private static Set<String> prefixPaths(Object v) {
    Set<String> out = new HashSet<>();
    for (String p : dev.camada.Config.strings(v)) {
      out.add(Paths.dirKey(p));
    }
    return out;
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
    Set<String> exact = m == null ? Set.of() : exactPaths(m.get("pathsExact"));
    Set<String> prefix = m == null ? Set.of() : prefixPaths(m.get("pathsPrefix"));
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

  /** Longest ua/header/path value a {@code matches} regex reads, in UTF-16 code units. */
  public static final int MAX_MATCH_INPUT = 2048;

  /**
   * One value through a {@code matches} regex. Over the cap the regex never runs (never truncate):
   * a deny rule hits, a skip rule misses.
   */
  private static boolean capped(Pattern rx, String v, boolean deny) {
    return v.length() > MAX_MATCH_INPUT ? deny : find(rx, v, deny);
  }

  /** Deletes every [\x00-\x1f\x7f] char: no engine then disagrees about a trailing newline. */
  static String stripControls(String v) {
    int n = v.length();
    int i = 0;
    while (i < n && !isControl(v.charAt(i))) {
      i++;
    }
    if (i == n) {
      return v;
    }
    StringBuilder sb = new StringBuilder(n).append(v, 0, i);
    for (; i < n; i++) {
      char ch = v.charAt(i);
      if (!isControl(ch)) {
        sb.append(ch);
      }
    }
    return sb.toString();
  }

  private static boolean isControl(char ch) {
    return ch < 0x20 || ch == 0x7f;
  }

  /**
   * A pattern this runtime cannot run against this input answers {@code false} and never throws:
   * java.util.regex recurses per group iteration, so a nested quantifier against a long path or
   * user agent overflows the request thread's stack where JS and Python's engines would not. The
   * legacy path list uses this; a v5 rule uses {@link #find(Pattern, String, boolean)}.
   */
  public static boolean find(Pattern rx, String input) {
    return find(rx, input, false);
  }

  /**
   * As {@link #find(Pattern, String)}, with {@code onFailure} as the answer when the engine fails
   * (a StackOverflowError or any RuntimeException from the matcher): a deny rule passes true so a
   * failure fails closed like an over-cap value, a skip rule passes false. The input is matched as
   * JS reads it, in UTF-16 code units: see {@link #unitView}.
   */
  public static boolean find(Pattern rx, String input, boolean onFailure) {
    long[] left = REQUEST_LEFT.get();
    if (left != null && left[0] <= 0) {
      return onFailure; // the request's regex budget is spent: answer like an over-cap value
    }
    long start = System.nanoTime();
    long budget = MATCH_BUDGET_MS * 1_000_000L;
    if (left != null) {
      budget = Math.min(budget, left[0]);
    }
    try {
      return rx.matcher(new Deadline(unitView(input), start + budget)).find();
    } catch (StackOverflowError | RuntimeException e) { // incl. Deadline.RegexBudgetExceeded
      return onFailure;
    } finally {
      if (left != null) {
        left[0] -= System.nanoTime() - start;
      }
    }
  }

  /** The code point standing for the surrogate code unit {@code u} (plane-15 private use). */
  static int standIn(int u) {
    return 0xF0000 + (u - 0xD800);
  }

  /** Appends {@code c}, or its stand-in if it is a surrogate. */
  private static void appendUnit(StringBuilder sb, char c) {
    if (Character.isSurrogate(c)) {
      sb.appendCodePoint(standIn(c));
    } else {
      sb.append(c);
    }
  }

  /**
   * {@code s} with every surrogate code unit as its stand-in, so java.util.regex (which reads code
   * points) sees the one-unit-per-char string JS does; {@code s} itself when it has none.
   */
  static String unitView(String s) {
    int i = 0;
    while (i < s.length() && !Character.isSurrogate(s.charAt(i))) {
      i++;
    }
    if (i == s.length()) {
      return s;
    }
    StringBuilder sb = new StringBuilder(s.length() + 8).append(s, 0, i);
    for (; i < s.length(); i++) {
      appendUnit(sb, s.charAt(i));
    }
    return sb.toString();
  }

  /** Longest one customer regex may run, in milliseconds (contract regex-limit v1). */
  public static final int MATCH_BUDGET_MS = 50;

  /** Total regex time one request's rule walk may spend, in milliseconds. */
  public static final int REQUEST_REGEX_BUDGET_MS = 100;

  /** Nanoseconds of regex budget left for the rule walk on this thread; null outside a walk. */
  private static final ThreadLocal<long[]> REQUEST_LEFT = new ThreadLocal<>();

  /** Opens the per-request regex budget; the walk calls {@link #closeRequestBudget} in finally. */
  static void openRequestBudget() {
    REQUEST_LEFT.set(new long[] {REQUEST_REGEX_BUDGET_MS * 1_000_000L});
  }

  static void closeRequestBudget() {
    REQUEST_LEFT.remove();
  }

  /**
   * A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
   * authored as JS regexes (the analyst validates them with {@code new RegExp}), so the JS
   * spellings java.util.regex reads differently are translated first — see {@link #jsToJava} — and
   * the default (non-UNICODE_CHARACTER_CLASS) mode keeps \d \w as JS reads them (ASCII). \s \S \b
   * \B are rewritten (see jsToJava) because Java 17's \s is ASCII-only and its \b counts non-ASCII
   * letters as word chars. A JS-valid pattern this runtime rejects (null, so the rule never fires)
   * is logged once per process, whatever the reason: see {@link Guarded#logOnce}. It matches code
   * units, as JS does: run it through {@link #find}, not {@code matcher} on the raw input.
   */
  public static Pattern compileRegex(String pattern) {
    return compileRegex(pattern, 0);
  }

  /** As {@link #compileRegex(String)} with flags: a path regex runs CASE_INSENSITIVE (§D3). */
  public static Pattern compileRegex(String pattern, int flags) {
    try {
      // JS /i and (?i: fold non-ASCII letters too; Java's i alone folds only ASCII (u is inert
      // where i is off). Java's u also folds a few letters JS's non-u /i does not (U+212A to k,
      // U+017F to s, U+0130 and U+0131 to i)
      return Pattern.compile(jsToJava(pattern), flags | Pattern.UNICODE_CASE);
    } catch (RuntimeException | StackOverflowError e) {
      String why =
          e instanceof PatternSyntaxException pse
              ? pse.getDescription()
              : e instanceof IllegalArgumentException && e.getMessage() != null
                  ? e.getMessage()
                  : e.getClass().getSimpleName();
      if (pattern == null) {
        return null;
      }
      String clip = pattern.length() > 200 ? pattern.substring(0, 200) : pattern;
      String shown = clip.replace("\n", "\\n").replace("\r", "\\r");
      Guarded.logOnce(
          clip + pattern.length() + ":" + pattern.hashCode(),
          "[camada] regex never matches on this runtime, rule fails open: /" + shown + "/ " + why);
      return null;
    }
  }

  // JS's \s is Unicode White_Space without U+0085, plus U+FEFF; Java's \s is ASCII-only. One
  // property lookup per char, where a list of the members is tested one by one.
  private static final String JS_SPACE = "[\\p{IsWhite_Space}\\uFEFF&&[^\\x85]]";
  private static final String JS_NON_SPACE = "[^" + JS_SPACE.substring(1);
  // what JS's . matches: not \n \r U+2028 U+2029; an (?m: ^ or $ needs none of it beside it
  private static final String JS_NON_TERMINATOR = "[^\\n\\r\\u2028-\\u2029]";
  // \b over Java's ASCII \w (its own \b counts non-ASCII letters as word chars)
  private static final String WORD_BOUNDARY = "(?:(?<=\\w)(?!\\w)|(?<!\\w)(?=\\w))";
  private static final String NON_WORD_BOUNDARY = "(?:(?<=\\w)(?=\\w)|(?<!\\w)(?!\\w))";

  /**
   * The JS spellings a tenant is likely to author and Java reads differently: {@code [^]} (any
   * char) -> {@code [\s\S]}, {@code \cX} -> the control character (Java's own \c reads a lower-case
   * letter differently), a bare {@code $} -> {@code \z} (Java's $ also accepts a final newline;
   * JS's does not; inside {@code (?m:} a {@code ^} and {@code $} -> lookarounds on \n \r U+2028
   * U+2029), and a named group {@code (?<name>} -> a plain {@code (} (JS admits {@code _} and
   * {@code $} in a name, Java only letters and digits; nothing in the SDK reads the names), {@code
   * []} -> {@code (?!)} (never matches), a JS identity escape ({@code \p}, {@code \Q}, {@code \k}
   * with no named group, an x or u escape without its hex digits) -> the bare letter, a {@code \c}
   * with no letter -> a literal backslash and {@code c}, a left brace that opens no {@code {n}},
   * {@code {n,}} or {@code {n,m}} quantifier -> escaped (JS reads it as a literal, Java throws), a
   * {@code .} -> {@code [^\n\r\u2028-\u2029]} (JS's also matches U+0085, Java's does not; kept as
   * is inside an {@code (?s:} group), and a {@code [} or {@code &&} inside a class -> escaped (Java
   * reads a union / an intersection), {@code \v} -> {@code \x0B}, {@code [\b]} -> backspace, {@code
   * \s \S} -> JS's whitespace set (a nested class, so a range next to it stays valid), {@code \b
   * \B} outside a class -> lookarounds on Java's ASCII {@code \w}, and a decimal escape: a
   * back-reference (or {@code \k<name>}) -> what reads the group as JS does, see below; anything
   * else -> an Annex B legacy octal {@code \xHH} (or the bare digit for 8 and 9). Anything else the
   * engine rejects still fails open.
   *
   * <p>JS (no {@code u} flag) reads UTF-16 code units, Java code points, so each surrogate unit is
   * a stand-in code point on both sides (see {@link #unitView}): a raw or {@code \\uD83D}-escaped
   * one in the pattern, a class range over D800-DFFF split around the block, and a lookbehind opens
   * with an empty group holding a supplementary char, which makes Java count its length in code
   * points.
   *
   * <p>A back-reference is emitted as a numeric Java reference to the group's number in the output
   * (Java rejects a named reference to a group not yet defined in the text, but accepts a numeric
   * one). A back-reference JS always reads as unset (to a group that encloses it, sits in another
   * alternative, is inside a negative lookaround, or is not yet evaluated, which runs right to left
   * in a lookbehind) -> {@code (?:)}, which JS matches as empty. One to a group that is certainly
   * set -> {@code (?:\J)}, J being the Java number of the group. Any other -> {@code
   * (?:\J|(?!\K))}, with the group wrapped as {@code (?:(...)())} so the empty marker group (Java
   * number K, opened just after the group closes) is set exactly when the group is: Java fails a
   * back-reference to an unset group, JS matches it as empty. A {@code \k<name>} reads every
   * definition of the name (ES2025 duplicates). A back-reference inside a lookbehind to a group JS
   * evaluates before it (one to its right in the lookbehind, as JS runs it right to left) cannot be
   * expressed, since Java runs a lookbehind left to right and reads that group as unset: it throws
   * IllegalArgumentException and compileRegex returns null, logged once. One to a group on its left
   * in the same lookbehind reads as unset in JS too, and compiles to {@code (?:)}.
   *
   * <p>Residuals, where Java cannot unset a capture: (A) a group inside a loop that an earlier
   * iteration set and this one skipped, read in the {@code (?:...)} alternation form: {@code
   * ^(?:(a)?b\1)+$} on "abab" is true in JS and false here; {@code ^(?:(a)|c)*\1b$} on "acab" is
   * false in JS and true here. (B) a capture leaking out of a positive lookaround: {@code
   * ^(?:(?=(a))ab|a)\1b$} on "ab" is true in JS and false here. (C) the lookbehind back-references
   * to a later group, which fail open (see above). (D) Java's loops ({@code *}, {@code +}, {@code
   * {n,m}}) do not restore captures when they backtrack out of an iteration or move to the next
   * find() start, so a MAYBE or SET reference to a group under such a loop may read a stale value:
   * {@code ^(b)*\1b$} on "b" is true in JS and false here (the old build was false too; the marker
   * form never matches less than the old {@code (?:\N)}). Nothing the backend accepts since
   * camada-all-xuxq carries a back-reference, so reopen this if that screen is relaxed.
   */
  static String jsToJava(String pattern) {
    StringBuilder out = new StringBuilder(pattern.length() + 8);
    int n = pattern.length();
    boolean inClass = false;
    int atomEnd = 0; // in a class: where the atom (or range) being walked ends
    Refs refs = scanRefs(pattern);
    Group cur = refs.root; // the group the walk is in
    int i = 0;
    while (i < n) {
      char ch = pattern.charAt(i);
      if (inClass && i >= atomEnd && ch != ']') { // a true atom start: maybe a range
        int[] lo = classAtom(pattern, i);
        atomEnd = lo[1];
        if (lo[0] >= 0
            && lo[1] + 1 < n
            && pattern.charAt(lo[1]) == '-'
            && pattern.charAt(lo[1] + 1) != ']') {
          int[] hi = classAtom(pattern, lo[1] + 1);
          if (hi[0] >= 0) {
            atomEnd = hi[1];
            if (lo[0] <= hi[0] && lo[0] <= 0xDFFF && hi[0] >= 0xD800) {
              splitRange(out, lo[0], hi[0]);
              i = hi[1];
              continue;
            }
          }
        }
      }
      if (ch == '\\' && i + 1 < n) {
        char nxt = pattern.charAt(i + 1);
        if (nxt == 'c') {
          char l = i + 2 < n ? pattern.charAt(i + 2) : 0;
          boolean ok = isAsciiLetter(l) || (inClass && ((l >= '0' && l <= '9') || l == '_'));
          if (ok) {
            out.append(String.format("\\x%02X", l & 0x1F));
            i += 3;
          } else {
            out.append("\\\\c"); // a literal backslash and c, as JS reads a bare \c
            i += 2;
          }
          continue;
        }
        if (nxt == 'u' && hexRun(pattern, i + 2, 4)) {
          int u = HexFormat.fromHexDigits(pattern, i + 2, i + 6);
          if (u >= 0xD800 && u <= 0xDFFF) {
            out.appendCodePoint(standIn(u));
            i += 6;
            continue;
          }
        }
        Emit ref = refs.text.get(i);
        if (ref != null) {
          out.append(ref.text);
          i = ref.end;
          continue;
        }
        String sub =
            switch (nxt) {
              case 'v' -> "\\x0B";
              case 'b' -> inClass ? "\\x08" : WORD_BOUNDARY;
              case 'B' -> inClass ? null : NON_WORD_BOUNDARY; // [\B] is an identity escape
              case 's' -> JS_SPACE;
              case 'S' -> JS_NON_SPACE;
              default -> null;
            };
        if (sub != null) {
          out.append(sub);
          i += 2;
          continue;
        }
        if (nxt >= '0' && nxt <= '9') {
          if (nxt >= '8') {
            out.append(nxt);
            i += 2;
            continue;
          }
          int[] oct = octal(pattern, i);
          out.append(String.format("\\x%02X", oct[0]));
          i = oct[1];
          continue;
        }
        // a JS identity escape keeps only the letter (\p is p, \x{41} is x{41}); an unresolved \k
        // in a pattern with named groups stays, and Java rejects it (fail open)
        boolean identity =
            isAsciiLetter(nxt)
                && !passesThrough(nxt)
                && !(nxt == 'x' && hexRun(pattern, i + 2, 2))
                && !(nxt == 'u' && hexRun(pattern, i + 2, 4))
                && !(nxt == 'k' && refs.namedGroups && !inClass);
        if (!identity) {
          out.append(ch);
        }
        appendUnit(out, nxt);
        i += 2;
        continue;
      }
      if (inClass) {
        // JS reads a [ or && inside a class as literals; Java reads a union / an intersection
        if (ch == '[' || (ch == '&' && i + 1 < n && pattern.charAt(i + 1) == '&')) {
          out.append('\\').append(ch);
          i++;
          continue;
        }
        inClass = ch != ']';
      } else if (ch == '[') {
        if (pattern.startsWith("[]", i)) {
          out.append("(?!)"); // JS's empty class never matches
          i += 2;
          continue;
        }
        if (pattern.startsWith("[^]", i)) {
          out.append("[\\s\\S]");
          i += 3;
          continue;
        }
        inClass = true;
        atomEnd = i + (pattern.startsWith("^", i + 1) ? 2 : 1); // a ^ right after [ negates
      } else if (ch == '{') {
        int end = quantifierEnd(pattern, i);
        if (end < 0) {
          out.append("\\{");
          i++;
        } else {
          out.append(clampBounds(pattern.substring(i, end)));
          i = end;
        }
        continue;
      } else if (ch == '$') {
        out.append(cur.multiline ? "(?!" + JS_NON_TERMINATOR + ")" : "\\z");
        i++;
        continue;
      } else if (ch == '^' && cur.multiline) {
        out.append("(?<!" + JS_NON_TERMINATOR + ")");
        i++;
        continue;
      } else if (ch == '.') {
        // JS's . excludes only \n \r U+2028 U+2029; Java's also excludes U+0085
        out.append(cur.dotAll ? "." : JS_NON_TERMINATOR);
        i++;
        continue;
      } else if (ch == ')') {
        Group closed = cur;
        if (closed.parent != null) { // a stray ) at the root stays as is
          cur = closed.parent;
          if (closed.marked) {
            out.append(")())");
            i++;
            continue;
          }
        }
      } else if (ch == '(') {
        cur = refs.groups.get(i);
        if (cur.cap > 0) {
          out.append(cur.marked ? "(?:(" : "(");
          int close = nameEnd(pattern, i);
          i = close > 0 ? close + 1 : i + 1;
          continue;
        }
        if (cur.kind == 'b' || cur.kind == 'B') {
          out.append(pattern, i, i + 4)
              .append("(?:")
              .appendCodePoint(standIn(0xD800))
              .append("){0}");
          i += 4;
          continue;
        }
      }
      appendUnit(out, ch);
      i++;
    }
    return out.toString();
  }

  /**
   * The class atom at {@code i} as {value, end}: its code unit as JS reads it, or -1 for a class
   * escape (\d \w \s and their negations) or one it is unsure of.
   */
  private static int[] classAtom(String p, int i) {
    int n = p.length();
    char ch = p.charAt(i);
    if (ch != '\\' || i + 1 >= n) {
      return new int[] {ch, i + 1};
    }
    char nx = p.charAt(i + 1);
    if (nx == 'u' && hexRun(p, i + 2, 4)) {
      return new int[] {HexFormat.fromHexDigits(p, i + 2, i + 6), i + 6};
    }
    if (nx == 'x' && hexRun(p, i + 2, 2)) {
      return new int[] {HexFormat.fromHexDigits(p, i + 2, i + 4), i + 4};
    }
    if (nx == 'c') {
      char l = i + 2 < n ? p.charAt(i + 2) : 0;
      boolean ok = isAsciiLetter(l) || (l >= '0' && l <= '9') || l == '_';
      return ok ? new int[] {l & 0x1F, i + 3} : new int[] {-1, i + 2};
    }
    if (nx >= '0' && nx <= '7') {
      return octal(p, i);
    }
    int v =
        switch (nx) {
          case 'b' -> 8;
          case 'f' -> '\f';
          case 'n' -> '\n';
          case 'r' -> '\r';
          case 't' -> '\t';
          case 'v' -> 0x0B;
          case 'd', 'D', 'w', 'W', 's', 'S' -> -1;
          default -> nx;
        };
    return new int[] {v, i + 2};
  }

  /**
   * The Annex B legacy octal escape at {@code i} as {value, end}: up to three digits, at most \377
   */
  private static int[] octal(String p, int i) {
    char d = p.charAt(i + 1);
    int v = d - '0';
    int j = i + 2;
    for (int max = d <= '3' ? 2 : 1; max > 0 && j < p.length(); max--, j++) {
      char o = p.charAt(j);
      if (o < '0' || o > '7') {
        break;
      }
      v = v * 8 + (o - '0');
    }
    return new int[] {v, j};
  }

  /**
   * A class range lo-hi that overlaps D800-DFFF: BMP pieces as they are, the block as stand-ins.
   */
  private static void splitRange(StringBuilder out, int lo, int hi) {
    if (lo < 0xD800) {
      out.append(String.format("\\x{%X}-\\x{%X}", lo, Math.min(hi, 0xD7FF)));
    }
    out.appendCodePoint(standIn(Math.max(lo, 0xD800)))
        .append('-')
        .appendCodePoint(standIn(Math.min(hi, 0xDFFF)));
    if (hi > 0xDFFF) {
      out.append(String.format("\\x{%X}-\\x{%X}", Math.max(lo, 0xE000), hi));
    }
  }

  /** The state of flag {@code flag} inside the group opening at {@code at}: {@code (?on-off:}. */
  private static boolean modifier(String p, int at, char flag, boolean cur) {
    int j = at + 1;
    if (j >= p.length() || p.charAt(j) != '?') {
      return cur;
    }
    j++;
    boolean on = true;
    boolean res = cur;
    while (j < p.length() && (isAsciiLetter(p.charAt(j)) || p.charAt(j) == '-')) {
      if (p.charAt(j) == '-') {
        on = false;
      } else if (p.charAt(j) == flag) {
        res = on;
      }
      j++;
    }
    return j < p.length() && p.charAt(j) == ':' ? res : cur;
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  /** Whether {@code s} has {@code len} hex digits from {@code at}. */
  private static boolean hexRun(String s, int at, int len) {
    if (at + len > s.length()) {
      return false;
    }
    for (int j = at; j < at + len; j++) {
      if (!HexFormat.isHexDigit(s.charAt(j))) {
        return false;
      }
    }
    return true;
  }

  /** The letters JS and Java read alike after a backslash (the rest are handled apart). */
  private static boolean passesThrough(char c) {
    return "dDwWfnrt".indexOf(c) >= 0;
  }

  /** For a ( at i: whether it opens a capturing group, plain or named. */
  private static boolean isCapture(String p, int i) {
    return i + 1 >= p.length() || p.charAt(i + 1) != '?' || nameEnd(p, i) > 0;
  }

  /** For a ( at i: the index of the > that closes a {@code (?<name>}, else -1. */
  private static int nameEnd(String p, int i) {
    boolean named =
        p.startsWith("?<", i + 1) && !p.startsWith("?<=", i + 1) && !p.startsWith("?<!", i + 1);
    return named ? p.indexOf('>', i + 3) : -1;
  }

  /** The index just past the digit run at {@code at}. */
  private static int digitsEnd(String p, int at) {
    while (at < p.length() && p.charAt(at) >= '0' && p.charAt(at) <= '9') {
      at++;
    }
    return at;
  }

  /** One group of the pattern: kind c capture, o other, = ! lookahead, b B lookbehind. */
  private static final class Group {
    final Group parent;
    final int alt; // which alternative of the parent it sits in
    final char kind;
    final int start;
    final int cap; // its capture number, 0 if not a capture
    final boolean dotAll; // inside an (?s: group, where . already matches everything
    final boolean multiline; // inside an (?m: group, where ^ and $ also match at line breaks
    int alts = 1;
    boolean minZero; // a quantifier after its ) allows zero repeats
    boolean marked; // read as maybe-unset: wrapped with an empty marker group after it
    int jn; // Java group number of the capture in the output
    int mn; // Java group number of its marker, if marked

    Group(Group parent, int alt, char kind, int start, int cap, boolean dotAll, boolean multiline) {
      this.parent = parent;
      this.alt = alt;
      this.kind = kind;
      this.start = start;
      this.cap = cap;
      this.dotAll = dotAll;
      this.multiline = multiline;
    }

    boolean negative() {
      return kind == '!' || kind == 'B';
    }

    boolean lookaround() {
      return "=!bB".indexOf(kind) >= 0;
    }
  }

  /** A back-reference: where it ends, the group and alternative holding it, the number or name. */
  private record Ref(int at, int end, Group in, int alt, int num, String name) {}

  /** A back-reference with the live target groups and how JS reads the last of them. */
  private record Decided(Ref r, List<Integer> live, Read read) {}

  /** What the walk emits for a back-reference, and where it resumes. */
  private record Emit(String text, int end) {}

  /** The group tree and what the walk emits for each back-reference. */
  private static final class Refs {
    final Group root = new Group(null, 0, 'o', 0, 0, false, false);
    final Map<Integer, Group> groups = new HashMap<>(); // by offset of the (
    final Map<Integer, Emit> text = new HashMap<>(); // by offset of the backslash
    boolean namedGroups;
  }

  /** The kind of the group opening at the ( at {@code i}. */
  private static char kindAt(String p, int i) {
    if (isCapture(p, i)) {
      return 'c';
    }
    if (p.startsWith("?=", i + 1)) {
      return '=';
    }
    if (p.startsWith("?!", i + 1)) {
      return '!';
    }
    if (p.startsWith("?<=", i + 1)) {
      return 'b';
    }
    return p.startsWith("?<!", i + 1) ? 'B' : 'o';
  }

  /**
   * The pre-pass: lexes as the walk does, builds the group tree, and decides for each resolvable
   * back-reference whether JS reads its group as unset, set, or either (see jsToJava).
   */
  private static Refs scanRefs(String p) {
    int n = p.length();
    Refs refs = new Refs();
    Group top = refs.root;
    List<Group> caps = new ArrayList<>();
    Map<String, List<Integer>> names = new HashMap<>();
    List<Ref> sites = new ArrayList<>();
    List<Group> events = new ArrayList<>(); // capture opens and closes, in output order
    boolean inClass = false;
    for (int i = 0; i < n; i++) {
      char ch = p.charAt(i);
      if (ch == '\\') {
        char nx = i + 1 < n && !inClass ? p.charAt(i + 1) : 0;
        if (nx == 'k' && i + 2 < n && p.charAt(i + 2) == '<') {
          int close = p.indexOf('>', i + 3);
          if (close > 0) {
            sites.add(new Ref(i, close + 1, top, top.alts - 1, 0, p.substring(i + 3, close)));
          }
        } else if (nx >= '1' && nx <= '9') {
          int end = digitsEnd(p, i + 1);
          if (end - i - 1 <= 9) {
            sites.add(
                new Ref(
                    i, end, top, top.alts - 1, Integer.parseInt(p.substring(i + 1, end)), null));
          }
        }
        i++;
      } else if (inClass) {
        inClass = ch != ']';
      } else if (ch == '[') {
        inClass = true;
      } else if (ch == '|') {
        top.alts++;
      } else if (ch == '(') {
        char kind = kindAt(p, i);
        int cap = kind == 'c' ? caps.size() + 1 : 0;
        boolean dotAll = modifier(p, i, 's', top.dotAll);
        boolean multiline = modifier(p, i, 'm', top.multiline);
        top = new Group(top, top.alts - 1, kind, i, cap, dotAll, multiline);
        refs.groups.put(i, top);
        if (cap > 0) {
          caps.add(top);
          events.add(top);
          int close = nameEnd(p, i);
          if (close > 0) {
            names.computeIfAbsent(p.substring(i + 3, close), k -> new ArrayList<>()).add(cap);
          }
        }
      } else if (ch == ')' && top.parent != null) {
        top.minZero = minZero(p, i + 1);
        if (top.cap > 0) {
          events.add(top);
        }
        top = top.parent;
      }
    }
    refs.namedGroups = !names.isEmpty();
    List<Decided> decided = new ArrayList<>();
    for (Ref r : sites) {
      List<Integer> targets = r.name == null ? List.of(r.num) : names.get(r.name);
      if (targets == null || r.num > caps.size()) {
        continue; // unresolved: the walk leaves it
      }
      Set<Group> around = new HashSet<>(); // the groups holding r
      for (Group g = r.in; g != null; g = g.parent) {
        around.add(g);
      }
      List<Integer> live = new ArrayList<>();
      Read read = Read.UNSET; // of the last live target: the only one when live has one
      for (int c : targets) {
        Read rd = readOf(caps.get(c - 1), r, around);
        if (rd != Read.UNSET) {
          live.add(c);
          read = rd;
        }
      }
      if (read == Read.MAYBE || live.size() > 1) {
        for (int c : live) {
          caps.get(c - 1).marked = true;
        }
      }
      decided.add(new Decided(r, live, read));
    }
    // number the groups as Java will see them: a marker opens as its group closes
    int next = 0;
    Set<Group> opened = new HashSet<>();
    for (Group g : events) {
      if (opened.add(g)) {
        g.jn = ++next;
      } else if (g.marked) {
        g.mn = ++next;
      }
    }
    for (Decided d : decided) {
      String text;
      if (d.live.isEmpty()) {
        text = "(?:)";
      } else if (d.live.size() == 1 && d.read == Read.SET) {
        text = "(?:\\" + caps.get(d.live.get(0) - 1).jn + ")";
      } else {
        StringBuilder sb = new StringBuilder("(?:");
        for (int c : d.live) {
          sb.append('\\').append(caps.get(c - 1).jn).append('|');
        }
        for (int c : d.live) {
          sb.append("(?!\\").append(caps.get(c - 1).mn).append(')');
        }
        text = sb.append(')').toString();
      }
      refs.text.put(d.r.at, new Emit(text, d.r.end));
    }
    return refs;
  }

  private enum Read {
    UNSET, // JS always reads the group as unset here
    SET, // JS always reads it as set
    MAYBE
  }

  /**
   * How JS reads capture {@code cap} at back-reference {@code r}; {@code around} holds r's groups.
   */
  private static Read readOf(Group cap, Ref r, Set<Group> around) {
    if (around.contains(cap)) {
      return Read.UNSET;
    }
    Group cn = cap; // the child of the lowest common group l on cap's side
    while (!around.contains(cn.parent)) {
      cn = cn.parent;
    }
    Group l = cn.parent;
    Group cp = r.in; // and on r's side (r itself when it sits directly in l)
    while (cp != l && cp.parent != l) {
      cp = cp.parent;
    }
    int pAlt = cp == l ? r.alt : cp.alt;
    int pAt = cp == l ? r.at : cp.start;
    if (cn.alt != pAlt) {
      return Read.UNSET;
    }
    boolean certain = !cap.minZero;
    for (Group g = cap.parent; g != l; g = g.parent) {
      if (g.negative()) {
        return Read.UNSET;
      }
      certain &= g.alts == 1 && !g.minZero;
    }
    Group look = l;
    while (look != null && !look.lookaround()) {
      look = look.parent;
    }
    boolean before = cn.start < pAt;
    boolean behind = look != null && (look.kind == 'b' || look.kind == 'B');
    if (behind && !before) { // JS (right to left) reads cap first; Java (left to right) cannot
      throw new IllegalArgumentException("back-reference to a later group inside a lookbehind");
    }
    if (before == behind) { // behind and before: JS has not evaluated cap yet
      return Read.UNSET;
    }
    return certain ? Read.SET : Read.MAYBE;
  }

  /**
   * Whether the quantifier at {@code at} allows zero repeats: {@code ?}, {@code *}, {@code {0..}}.
   */
  private static boolean minZero(String p, int at) {
    if (at >= p.length()) {
      return false;
    }
    char q = p.charAt(at);
    if (q == '{' && quantifierEnd(p, at) > 0) {
      return p.substring(at + 1, digitsEnd(p, at + 1)).chars().allMatch(c -> c == '0');
    }
    return q == '?' || q == '*';
  }

  /**
   * A quantifier with each bound above Integer.MAX_VALUE clamped to it: Java rejects those, JS does
   * not.
   */
  private static String clampBounds(String q) {
    StringBuilder sb = new StringBuilder();
    for (String part : q.split("(?<=[{,])|(?=[,}])")) {
      boolean big =
          part.length() > 9
              && part.chars().allMatch(Character::isDigit)
              && new java.math.BigInteger(part)
                      .compareTo(java.math.BigInteger.valueOf(Integer.MAX_VALUE))
                  > 0;
      sb.append(big ? String.valueOf(Integer.MAX_VALUE) : part);
    }
    return sb.toString();
  }

  /** The index just past a {@code {n}}, {@code {n,}} or {@code {n,m}} at {@code i}, else -1. */
  private static int quantifierEnd(String s, int i) {
    int n = s.length();
    int j = i + 1;
    int digits = j;
    while (j < n && s.charAt(j) >= '0' && s.charAt(j) <= '9') {
      j++;
    }
    if (j == digits) {
      return -1;
    }
    if (j < n && s.charAt(j) == ',') {
      j++;
      while (j < n && s.charAt(j) >= '0' && s.charAt(j) <= '9') {
        j++;
      }
    }
    return j < n && s.charAt(j) == '}' ? j + 1 : -1;
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
  private static RuleCond compileCond(Map<String, Object> c, List<Pair> sets, boolean deny) {
    String f = String.valueOf(c.getOrDefault("f", ""));
    String op = String.valueOf(c.getOrDefault("op", ""));
    if (f.equals("path")) { // every path op reads the canonical forms (see Paths), never fieldValue
      Predicate<String> pred = pathPred(op, values(c.get("v")), deny);
      return r -> Paths.hit(pred, r.paths, deny);
    }
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
    List<String> values = values(c.get("v"));
    String first = values.isEmpty() ? "" : values.get(0);
    switch (op) {
      case "matches":
        Pattern rx = compileRegex(first);
        boolean strip = f.equals("ua") || f.equals("header");
        return r -> {
          String v = read.apply(r);
          if (v == null || rx == null) {
            return false;
          }
          if (strip) {
            String s = stripControls(v);
            if (s != v) {
              // control chars present: a deny rule tests raw and stripped, a skip never exempts
              return deny && (capped(rx, v, deny) || capped(rx, s, deny));
            }
          }
          return capped(rx, v, deny);
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

  private static List<String> values(Object raw) {
    List<String> values = new ArrayList<>();
    if (raw instanceof List<?> l) {
      for (Object x : l) {
        values.add(jsString(x));
      }
    } else {
      values.add(jsString(raw));
    }
    return values;
  }

  /** One path condition -> a predicate over a single path form (canonical values, §D3). */
  private static Predicate<String> pathPred(String op, List<String> values, boolean deny) {
    String first = values.isEmpty() ? "" : values.get(0);
    if (op.equals("matches")) {
      Pattern rx = compileRegex(first, Pattern.CASE_INSENSITIVE);
      return p -> rx != null && (p.length() > MAX_MATCH_INPUT ? deny : find(rx, p, deny));
    }
    if (op.equals("starts_with")) {
      String key = first.endsWith("/") ? Paths.dirKey(first) : Paths.canonPath(first);
      return p -> Paths.dir(p).startsWith(key);
    }
    Set<String> set = new HashSet<>();
    for (String v : values) {
      set.add(Paths.canonPath(v));
    }
    return set::contains;
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
            conds.add(compileCond(cm, sets, !action.equals("skip")));
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
      Pattern rx = compileRegex(p, Pattern.CASE_INSENSITIVE);
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
        exactPaths(meta.get("pathsExact")),
        prefixPaths(meta.get("pathsPrefix")),
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
