package dev.camada;

import dev.camada.Config.TrustedProxy;
import java.util.ArrayList;
import java.util.List;

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

  private static boolean validIp(String s) {
    return s.indexOf(':') < 0 ? IpParse.parseIp4(s) >= 0 : IpParse.parseIp6(s) != null;
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
   * The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config. Anything
   * unresolvable falls back to the peer (fail safe).
   */
  public static String resolveClientIp(String peer, String xff, TrustedProxy cfg) {
    // dual-stack v4-mapped form
    String sock = peer != null && peer.startsWith("::ffff:") ? peer.substring(7) : peer;
    if (cfg == null || "none".equals(cfg.mode()) || xff == null || xff.isEmpty()) {
      return sock;
    }
    List<String> entries = new ArrayList<>();
    for (String e : xff.split(",")) {
      if (!e.trim().isEmpty()) {
        entries.add(e.trim());
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
        for (int i = entries.size() - 1; i >= 0; i--) {
          String entry = entries.get(i);
          boolean isTrusted = false;
          for (Cidr t : trusted) {
            if (inCidr(entry, t)) {
              isTrusted = true;
              break;
            }
          }
          if (!isTrusted) {
            candidate = entry;
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
