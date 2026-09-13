package dev.camada.snapshot;

import dev.camada.IpParse;
import dev.camada.snapshot.Parser.CompiledRule;
import dev.camada.snapshot.Parser.RangeSet;
import dev.camada.snapshot.Parser.RuleCond;
import dev.camada.snapshot.Parser.RuleRequest;
import dev.camada.snapshot.Parser.Snapshot;
import java.nio.IntBuffer;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Matcher: sub-millisecond checks over a parsed Snapshot, ported from {@code @camada/core}
 * src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully synchronous
 * and allocation-light. The original's per-instance scratch request is not ported: a JS isolate
 * runs one match() at a time, but here one Matcher serves every request thread, so the rule loop
 * reads a RuleRequest built per call.
 *
 * <p>Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
 * first (first match wins, the order IS the precedence), then allow -> block -> challenge. Within
 * each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path. At the SDK position only
 * ip, path, ua and the request headers are usually known; asn/country/tlsx entries and conditions
 * then simply never match — that is the documented, honest enforcement scope (fail open, never
 * guess).
 */
public final class Matcher {
  /**
   * What one match() reads. {@code ua} feeds the v5 rules only (the three sides never read it);
   * {@code header} is the v5 header-condition getter, always called with a lower-cased name.
   */
  public record MatchInput(
      String ip,
      Long asn,
      String country,
      String tlsx,
      String path,
      String ua,
      Function<String, String> header) {
    public static MatchInput ip(String ip) {
      return new MatchInput(ip, null, null, null, null, null, null);
    }

    public MatchInput withAsn(Long asn) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }

    public MatchInput withCountry(String country) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }

    public MatchInput withTlsx(String tlsx) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }

    public MatchInput withPath(String path) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }

    public MatchInput withUa(String ua) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }

    public MatchInput withHeader(Function<String, String> header) {
      return new MatchInput(ip, asn, country, tlsx, path, ua, header);
    }
  }

  /**
   * {@code allowed} is true for skip (which absorbed the old allow) and for the allow side; {@code
   * action} is the action of the rule that decided (null when a side did); {@code rule} the rule
   * id, present only when reason is 'rule'; {@code reason} is ip4 | ip6 | asn | country | tls |
   * path | rule | cold, or null when nothing matched.
   */
  public record MatchResult(
      boolean block,
      boolean challenge,
      boolean allowed,
      boolean warn,
      String action,
      String rule,
      String reason,
      String version) {
    public static final MatchResult NONE =
        new MatchResult(false, false, false, false, null, null, null, null);

    static MatchResult of(
        boolean block, boolean challenge, boolean allowed, String reason, String version) {
      return new MatchResult(block, challenge, allowed, false, null, null, reason, version);
    }
  }

  public final Snapshot snap;

  public Matcher(Snapshot snap) {
    this.snap = snap;
  }

  public static String cleanPath(String raw) {
    String p = raw == null || raw.isEmpty() ? "/" : raw;
    int q = p.indexOf('?');
    return q < 0 ? p : p.substring(0, q);
  }

  /** Walks every '/'-terminated ancestor of {@code path}, the way the block side does. */
  private static boolean prefixHit(Set<String> prefixes, String path) {
    int i = path.indexOf('/', 1);
    while (i != -1) {
      if (prefixes.contains(path.substring(0, i + 1))) {
        return true;
      }
      i = path.indexOf('/', i + 1);
    }
    return false;
  }

  /**
   * A rule decided this request (§D3): at most one of allowed / block / challenge / warn is true,
   * {@code reason} is 'rule', and {@code rule} names the id the adapters stamp on the event.
   */
  private static MatchResult ruleResult(CompiledRule rule, String version) {
    String a = rule.action();
    return new MatchResult(
        a.equals("block"),
        a.equals("challenge"),
        a.equals("skip"),
        a.equals("warn"),
        a,
        rule.id(),
        "rule",
        version);
  }

  private static boolean bit(IntBuffer bm, int b) {
    return ((bm.get(b >>> 5) >>> (b & 31)) & 1) != 0;
  }

  private boolean blocked4(int n) {
    Snapshot s = snap;
    int b = n >>> 8;
    if (!bit(s.bm4(), b)) {
      return false;
    }
    int hi = n >>> 16;
    int left = s.idx4().get(hi);
    int right = s.idx4().get(hi + 1) - 1;
    if (left > 0) {
      left--;
    }
    if (right < left) {
      return false;
    }
    IntBuffer s4 = s.s4();
    while (left < right) {
      int m = (left + right + 1) >>> 1;
      if (Integer.compareUnsigned(s4.get(m), n) <= 0) {
        left = m;
      } else {
        right = m - 1;
      }
    }
    return Integer.compareUnsigned(s4.get(left), n) <= 0
        && Integer.compareUnsigned(n, s.e4().get(left)) <= 0;
  }

  private boolean blocked6(int[] w) {
    Snapshot s = snap;
    int b = w[0] >>> 8;
    if (!bit(s.bm6(), b)) {
      return false;
    }
    int left = 0;
    int right = s.n6() - 1;
    if (right < 0) {
      return false;
    }
    IntBuffer s6 = s.s6();
    while (left < right) {
      int m = (left + right + 1) >>> 1;
      if (Parser.cmpWords(s6, m * 4, w) <= 0) {
        left = m;
      } else {
        right = m - 1;
      }
    }
    int o = left * 4;
    return Parser.cmpWords(s6, o, w) <= 0 && Parser.cmpWords(s.e6(), o, w) >= 0;
  }

  private boolean blockedAsn(long asn) {
    Snapshot s = snap;
    if (asn < 0) {
      return false;
    }
    if (asn < 4194304) {
      return bit(s.asnBm(), (int) asn);
    }
    IntBuffer extra = s.asnExtra();
    int left = 0;
    int right = extra.limit() - 1;
    while (left <= right) {
      int m = (left + right) >>> 1;
      long v = Integer.toUnsignedLong(extra.get(m));
      if (v == asn) {
        return true;
      }
      if (v < asn) {
        left = m + 1;
      } else {
        right = m - 1;
      }
    }
    return false;
  }

  private boolean blockedPath(String path) {
    Snapshot s = snap;
    if (s.pathsExact().contains(path)) {
      return true;
    }
    if (!s.pathsPrefix().isEmpty() && prefixHit(s.pathsPrefix(), path)) {
      return true;
    }
    for (Pattern rx : s.pathsRegex()) {
      if (Parser.find(rx, path)) {
        return true;
      }
    }
    return false;
  }

  /** The block side: v3 sections plus the top-level meta. */
  private String blockSide(MatchInput i, long n4, int[] w) {
    Snapshot s = snap;
    if (n4 >= 0 && blocked4((int) n4)) {
      return "ip4";
    }
    if (w != null && blocked6(w)) {
      return "ip6";
    }
    if (i.asn() != null && blockedAsn(i.asn())) {
      return "asn";
    }
    if (i.country() != null && !i.country().isEmpty() && s.country().contains(i.country())) {
      return "country";
    }
    if (i.tlsx() != null && !i.tlsx().isEmpty() && s.tls().contains(i.tlsx())) {
      return "tls";
    }
    if ((!s.pathsExact().isEmpty() || !s.pathsPrefix().isEmpty() || !s.pathsRegex().isEmpty())
        && blockedPath(cleanPath(i.path()))) {
      return "path";
    }
    return null;
  }

  /** A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key. */
  private static String side(RangeSet st, MatchInput i, long n4, int[] w) {
    if (st.empty()) {
      return null; // the common v3 snapshot
    }
    if (n4 >= 0 && Parser.inRange4(st.r4(), (int) n4)) {
      return "ip4";
    }
    if (w != null && Parser.inRange6(st.r6(), st.n6(), w)) {
      return "ip6";
    }
    if (i.asn() != null && st.asn().contains(i.asn())) {
      return "asn";
    }
    if (i.country() != null && !i.country().isEmpty() && st.country().contains(i.country())) {
      return "country";
    }
    if (!st.pathsExact().isEmpty() || !st.pathsPrefix().isEmpty()) {
      String p = cleanPath(i.path());
      if (st.pathsExact().contains(p)) {
        return "path";
      }
      if (!st.pathsPrefix().isEmpty() && prefixHit(st.pathsPrefix(), p)) {
        return "path";
      }
    }
    return null;
  }

  public MatchResult match(MatchInput i) {
    Snapshot s = snap;
    String ip = i.ip() == null ? "" : i.ip();
    long n4 = -1;
    int[] w = null;
    if (!ip.isEmpty()) {
      if (ip.indexOf(':') < 0) {
        n4 = IpParse.parseIp4(ip);
      } else {
        w = IpParse.parseIp6(ip);
      }
    }
    if (!s.rules().isEmpty()) {
      RuleRequest r = new RuleRequest();
      r.n4 = n4;
      r.ip6 = w;
      r.asn = i.asn();
      r.country = i.country();
      r.tlsx = i.tlsx();
      r.path = cleanPath(i.path());
      r.ua = i.ua();
      r.header = i.header();
      for (CompiledRule rule : s.rules()) { // the order IS the precedence (§A4): first match wins
        boolean all = true;
        for (RuleCond cond : rule.conds()) {
          if (!cond.test(r)) {
            all = false;
            break;
          }
        }
        if (all) {
          return ruleResult(rule, s.version());
        }
      }
    }
    String reason = side(s.allow(), i, n4, w);
    if (reason != null) {
      return MatchResult.of(false, false, true, reason, s.version());
    }
    reason = blockSide(i, n4, w);
    if (reason != null) {
      return MatchResult.of(true, false, false, reason, s.version());
    }
    reason = side(s.challenge(), i, n4, w);
    if (reason != null) {
      return MatchResult.of(false, true, false, reason, s.version());
    }
    return MatchResult.of(false, false, false, null, s.version());
  }
}
