package dev.camada.snapshot;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Path canonicalisation (contracts §D3 "Path matching"), ported byte for byte from edge-analyst
 * src/blocklist.js canonPath / pathForms / pathHit. A path rule must catch every spelling a router
 * sends to the same handler, so both sides of a comparison are canonicalised: query cut at ? or #;
 * %XX decoded when it is printable ASCII other than / and % (so %2F never becomes a separator);
 * every other byte, raw non-ASCII included, written as lower-case %xx of its UTF-8; ASCII
 * lower-cased; each segment cut at its first ; (servlet path parameters); empty segments dropped;
 * and . / .. resolved — the {@code full} form. {@code lit} skips that last step. A deny fires when
 * raw, lit or full matches; an exemption (allow side, a skip rule) needs lit AND full.
 */
public final class Paths {
  private Paths() {}

  private static final char[] HEX = "0123456789abcdef".toCharArray();
  // already canonical: the common case skips the byte walk
  private static final Pattern CANON =
      Pattern.compile("^(?:/(?!\\.\\.?(?:/|$))[a-z0-9\\-._~!$&'()*+,=:@]+)+$");

  static String stripQuery(String raw) {
    String p = raw == null || raw.isEmpty() ? "/" : raw;
    int q = p.indexOf('?');
    int h = p.indexOf('#');
    if (h != -1 && (q == -1 || h < q)) {
      q = h;
    }
    return q == -1 ? p : p.substring(0, q);
  }

  private static int hexv(int c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  }

  public static String canonPath(String raw, boolean dots) {
    String p = stripQuery(raw);
    if (p.equals("/") || CANON.matcher(p).matches()) {
      return p;
    }
    byte[] b = p.getBytes(StandardCharsets.UTF_8);
    StringBuilder s = new StringBuilder(b.length + 8);
    for (int i = 0; i < b.length; i++) {
      int c = b[i] & 0xff;
      if (c == '%' && i + 2 < b.length && hexv(b[i + 1]) >= 0 && hexv(b[i + 2]) >= 0) {
        c = hexv(b[i + 1]) * 16 + hexv(b[i + 2]);
        i += 2;
        if (c == '/') {
          s.append("%2f");
          continue;
        }
      }
      if (c < 0x21 || c > 0x7e || c == '%') {
        s.append('%').append(HEX[c >> 4]).append(HEX[c & 15]);
        continue;
      }
      s.append((char) (c >= 'A' && c <= 'Z' ? c + 32 : c));
    }
    List<String> out = new ArrayList<>();
    for (String seg : s.toString().split("/", -1)) {
      int k = seg.indexOf(';');
      if (k != -1) {
        seg = seg.substring(0, k);
      }
      if (seg.isEmpty() || (dots && seg.equals("."))) {
        continue;
      }
      if (dots && seg.equals("..")) {
        if (!out.isEmpty()) {
          out.remove(out.size() - 1);
        }
        continue;
      }
      out.add(seg);
    }
    return "/" + String.join("/", out);
  }

  public static String canonPath(String raw) {
    return canonPath(raw, true);
  }

  /** [raw (query cut), lit, full] for one request path. */
  public static String[] forms(String raw) {
    String p = stripQuery(raw);
    if (p.equals("/") || CANON.matcher(p).matches()) {
      return new String[] {p, p, p};
    }
    return new String[] {p, canonPath(p, false), canonPath(p, true)};
  }

  static String dir(String p) {
    return p.endsWith("/") ? p : p + "/";
  }

  /** A prefix entry or a starts_with value ending in / -> its canonical directory key. */
  public static String dirKey(String v) {
    return dir(canonPath(v));
  }

  /** Walks '/' boundaries: /a/b tries /, /a/, /a/b/. */
  static boolean prefixed(Set<String> prefixes, String path) {
    String d = dir(path);
    for (int i = 0; i != -1; i = d.indexOf('/', i + 1)) {
      if (prefixes.contains(d.substring(0, i + 1))) {
        return true;
      }
    }
    return false;
  }

  /** deny (block/challenge/warn) = any spelling; allow/skip = both canonical forms. */
  static boolean hit(Predicate<String> pred, String[] forms, boolean deny) {
    return deny
        ? pred.test(forms[0]) || pred.test(forms[1]) || pred.test(forms[2])
        : pred.test(forms[1]) && pred.test(forms[2]);
  }
}
