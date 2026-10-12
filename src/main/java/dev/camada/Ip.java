package dev.camada;

import dev.camada.Config.TrustedProxy;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer: raw
 * X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration; a
 * spoofed XFF must not reach the analysis or the blocklist. Ported from {@code @camada/core}
 * src/ip.ts.
 */
public final class Ip {
  private Ip() {}

  /** A parsed CIDR: a v4 base (base6 null) or a v6 base as four words. */
  private record Cidr(long base4, int[] base6, int bits) {}

  private static final Pattern PORT = Pattern.compile(":[0-9]{1,5}");

  /**
   * One X-Forwarded-For entry with any port removed (camada-all-0vho): {@code [v6]:port} and {@code
   * [v6]} → v6, {@code a.b.c.d:port} → a.b.c.d. A bare IPv6 literal is returned whole (its last
   * group is never a port); anything else malformed comes back unchanged, so validation rejects it
   * and the peer wins.
   */
  static String stripPort(String e) {
    if (e.startsWith("[")) {
      int close = e.indexOf(']');
      if (close < 0) {
        return e;
      }
      String inner = e.substring(1, close);
      String rest = e.substring(close + 1);
      return inner.indexOf(':') >= 0 && (rest.isEmpty() || PORT.matcher(rest).matches())
          ? inner
          : e;
    }
    int colon = e.indexOf(':');
    if (colon < 0 || e.indexOf(':', colon + 1) >= 0) {
      return e; // no colon, or a bare IPv6 literal
    }
    String host = e.substring(0, colon);
    return IpParse.parseIp4(host) >= 0 && PORT.matcher(e.substring(colon)).matches() ? host : e;
  }

  /**
   * 127.0.0.0/8 or ::1, any spelling. The peer's {@code ::ffff:127.x.x.x} form is already reduced
   * to the dotted quad.
   */
  private static boolean isLoopback(String ip) {
    if (ip.indexOf(':') < 0) {
      long n = IpParse.parseIp4(ip);
      return n >= 0 && (n >>> 24) == 127;
    }
    int[] w = IpParse.parseIp6(ip);
    return w != null && w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 1;
  }

  private static boolean trusted(String ip, List<Cidr> trusted) {
    if (!validIp(ip)) {
      return false; // a non-IP XFF entry is never a trusted hop (C6 v3)
    }
    for (Cidr t : trusted) {
      if (inCidr(ip, t)) {
        return true;
      }
    }
    return false;
  }

  /**
   * A plain IPv4 or IPv6 address (C6 v3), by grammar alone: ASCII hex groups, so embedded dotted
   * quads, zone ids and brackets fail ({@link IpParse#parseIp6}); a single leading or trailing
   * {@code :} ({@code :8:8:8}, {@code 2001:db8::1:}) is rejected here. Never {@code InetAddress},
   * which accepts forms C6 rejects and resolves host names over DNS.
   */
  static boolean validIp(String s) {
    if (s.indexOf(':') < 0) {
      return IpParse.parseIp4(s) >= 0;
    }
    int n = s.length();
    if (n < 2
        || (s.charAt(0) == ':' && s.charAt(1) != ':')
        || (s.charAt(n - 1) == ':' && s.charAt(n - 2) != ':')) {
      return false;
    }
    return IpParse.parseIp6(s) != null;
  }

  /**
   * {@code ::ffff:a.b.c.d} (any case) → a.b.c.d, only when a valid dotted quad follows; anything
   * else is returned unchanged ({@code ::ffff:7f00:1} stays an ordinary IPv6 address).
   */
  static String unmap(String s) {
    if (s.length() < 14 || !s.regionMatches(true, 0, "::ffff:", 0, 7)) {
      return s;
    }
    String v4 = s.substring(7);
    return IpParse.parseIp4(v4) >= 0 ? v4 : s;
  }

  /**
   * Leading and trailing SP and HTAB only (HTTP OWS); never String.trim/strip, which remove more.
   */
  static String trimOws(String s) {
    int a = 0;
    int b = s.length();
    while (a < b && (s.charAt(a) == ' ' || s.charAt(a) == '\t')) {
      a++;
    }
    while (b > a && (s.charAt(b - 1) == ' ' || s.charAt(b - 1) == '\t')) {
      b--;
    }
    return s.substring(a, b);
  }

  private static Cidr parseCidr(String c) {
    int slash = c.indexOf('/');
    if (slash < 0) {
      return null;
    }
    String addr = c.substring(0, slash);
    int bits;
    try {
      bits = Integer.parseInt(c.substring(slash + 1));
    } catch (NumberFormatException e) {
      return null;
    }
    if (addr.indexOf(':') < 0) {
      long base = IpParse.parseIp4(addr);
      return base >= 0 && bits >= 0 && bits <= 32 ? new Cidr(base, null, bits) : null;
    }
    int[] words = IpParse.parseIp6(addr);
    return words != null && bits >= 0 && bits <= 128 ? new Cidr(-1, words, bits) : null;
  }

  private static boolean inCidr(String ip, Cidr cidr) {
    if (cidr.base6() == null) {
      long n = IpParse.parseIp4(ip);
      if (n < 0) {
        return false;
      }
      int bits = cidr.bits();
      long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
      return (n & mask) == (cidr.base4() & mask);
    }
    int[] words = IpParse.parseIp6(ip);
    if (words == null) {
      return false;
    }
    int remaining = cidr.bits();
    for (int k = 0; k < 4 && remaining > 0; k++) {
      int take = Math.min(32, remaining);
      int mask = take == 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - take));
      if ((words[k] & mask) != (cidr.base6()[k] & mask)) {
        return false;
      }
      remaining -= take;
    }
    return true;
  }

  /**
   * The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config (contract
   * C6 v3). The result is always a valid IP address or null, in every mode.
   *
   * <p>XFF entries are trimmed of space and tab only, read without a port ({@code ip:port}, {@code
   * [v6]:port}, as Azure writes them) and with {@code ::ffff:a.b.c.d} reduced to a.b.c.d, in every
   * mode (camada-all-0vho). Several XFF header lines arrive joined with {@code ", "}.
   *
   * <p>The peer is {@code getRemoteAddr()} with {@code ::ffff:} removed before a dotted quad, when
   * that is a valid IP; it is never trimmed or port-stripped. A non-empty peer that is not a valid
   * IP could not be read: the result falls back to null, never to the XFF walk. Null or empty means
   * no peer (a unix-socket listener).
   *
   * <p>{@code cidrs} (also what the dashboard's Cloudflare option stores) walks the chain {@code
   * [...xff, peer]} from the right (camada-all-yfc6): if the socket peer is not a trusted proxy,
   * the request did not come through one and the peer IS the client; XFF is ignored, since anyone
   * hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x)
   * counts as a trusted hop: a local front end or sidecar, which no remote client can be. Loopback
   * is trusted only as the peer, never as an XFF entry; an XFF entry that is not a valid IP is
   * never a trusted hop. With no peer at all the walk runs over XFF alone: the host's network edge
   * is trusted to have written it. {@code hops} and {@code vercel} trust XFF by definition and
   * ignore the peer.
   */
  public static String resolveClientIp(String peer, String xff, TrustedProxy cfg) {
    String mapped =
        peer == null || peer.isEmpty() ? null : unmap(peer); // dual-stack v4-mapped form
    String sock = mapped != null && validIp(mapped) ? mapped : null;
    if (cfg == null || "none".equals(cfg.mode()) || xff == null || xff.isEmpty()) {
      return sock;
    }
    List<String> entries = new ArrayList<>();
    for (String e : xff.split(",")) {
      String entry = unmap(stripPort(trimOws(e)));
      if (!entry.isEmpty()) {
        entries.add(entry);
      }
    }
    if (entries.isEmpty()) {
      return sock;
    }
    String candidate = null;
    switch (cfg.mode()) {
      case "hops":
        int hops = cfg.hops();
        if (hops >= 1 && hops <= entries.size()) {
          candidate = entries.get(entries.size() - hops);
        }
        break;
      case "vercel":
        candidate = entries.get(entries.size() - 1); // Vercel overwrites XFF: its rightmost is safe
        break;
      case "cidrs":
        List<Cidr> trusted = new ArrayList<>();
        for (String c : cfg.cidrs()) {
          Cidr parsed = parseCidr(c);
          if (parsed != null) {
            trusted.add(parsed);
          }
        }
        if (mapped != null && (sock == null || (!isLoopback(sock) && !trusted(sock, trusted)))) {
          return sock; // the peer is the first hop: no trusted proxy wrote this XFF; an unreadable
          // peer never walks
        }
        for (int i = entries.size() - 1; i >= 0; i--) {
          if (!trusted(entries.get(i), trusted)) {
            candidate = entries.get(i);
            break;
          }
        }
        break;
      default:
        break;
    }
    return candidate != null && validIp(candidate) ? candidate : sock;
  }
}
