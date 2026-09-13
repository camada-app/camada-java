package dev.camada.challenge;

import dev.camada.Json;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Wire constants and pure helpers for the SDK-served challenge (contracts §D2), ported from {@code
 * @camada/core} src/challenge/format.ts. Nothing here does crypto; {@link Kit} supplies HMAC and
 * SHA-256 from the JDK, so the format has exactly one definition across the family.
 */
public final class Format {
  private Format() {}

  public static final String CHALLENGE_COOKIE = "_cch";
  public static final long CHALLENGE_TTL_MS = 3_600_000L; // 1 h (contract)
  public static final int POW_BITS = 16; // leading zero bits of SHA-256("<nonce>.<solution>")
  public static final int NONCE_HEX = 32; // the nonce is the first 32 hex chars of the HMAC
  private static final long DAY_MS = 86_400_000L;
  private static final int MAX_RETURN_TO = 2048;
  private static final int MAX_SOLUTION = 32;

  public static long utcDay(long nowMs) {
    return Math.floorDiv(nowMs, DAY_MS);
  }

  // Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
  public static String nonceMessage(String ip, long day) {
    return "camada-challenge-nonce|" + (ip == null ? "" : ip) + "|" + day;
  }

  public static String tokenMessage(String ip, long exp) {
    return "camada-challenge-token|" + (ip == null ? "" : ip) + "|" + exp;
  }

  /** A split cookie value: the expiry and the mac. */
  public record Token(long exp, String mac) {}

  public static Token splitToken(String value) {
    if (value == null || value.isEmpty()) {
      return null;
    }
    int dot = value.indexOf('.');
    if (dot <= 0) {
      return null;
    }
    long exp;
    try {
      exp = Long.parseLong(value.substring(0, dot));
    } catch (NumberFormatException e) {
      return null;
    }
    String mac = value.substring(dot + 1);
    return mac.isEmpty() ? null : new Token(exp, mac);
  }

  /** Constant-time for equal-length strings; length itself is not a secret here. */
  public static boolean safeEqual(String a, String b) {
    return a.length() == b.length()
        && MessageDigest.isEqual(
            a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  /** True when the hex digest starts with {@code bits} zero bits. */
  public static boolean powOk(String hexDigest, int bits) {
    int nibbles = bits >> 2;
    int rest = bits & 3;
    if (hexDigest.length() < nibbles + (rest != 0 ? 1 : 0)) {
      return false;
    }
    for (int i = 0; i < nibbles; i++) {
      if (hexDigest.charAt(i) != '0') {
        return false;
      }
    }
    if (rest == 0) {
      return true;
    }
    int v = Character.digit(hexDigest.charAt(nibbles), 16);
    return v >= 0 && (v >> (4 - rest)) == 0;
  }

  public static boolean solutionShapeOk(String solution) {
    return solution != null && !solution.isEmpty() && solution.length() <= MAX_SOLUTION;
  }

  public static String challengeCookie(String value, boolean secure) {
    return CHALLENGE_COOKIE
        + "="
        + value
        + "; Path=/; Max-Age="
        + (CHALLENGE_TTL_MS / 1000)
        + "; HttpOnly; SameSite=Lax"
        + (secure ? "; Secure" : "");
  }

  /**
   * Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
   * protocol-relative '//host' redirect, a control character, or something absurdly long.
   */
  public static String safeReturnTo(String raw) {
    if (raw == null || raw.isEmpty() || raw.length() > MAX_RETURN_TO) {
      return "/";
    }
    if (raw.charAt(0) != '/'
        || (raw.length() > 1 && (raw.charAt(1) == '/' || raw.charAt(1) == '\\'))) {
      return "/";
    }
    for (int i = 0; i < raw.length(); i++) {
      char c = raw.charAt(i);
      if (c < 0x21 || c > 0x7E) {
        return "/";
      }
    }
    return raw;
  }

  /** A challenge page is only worth serving to a top-level HTML navigation (contract §D2). */
  public static boolean wantsHtml(String accept, String secFetchDest) {
    if (accept == null || !accept.contains("text/html")) {
      return false;
    }
    return secFetchDest == null || secFetchDest.isEmpty() || secFetchDest.equals("document");
  }

  public static String escapeAttr(String s) {
    return s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }

  /**
   * Safe to drop inside an inline script: {@code <} is escaped so no value can close the element
   * early.
   */
  public static String escapeScript(String s) {
    return Json.stringify(s).replace("<", "\\u003c");
  }

  /** application/x-www-form-urlencoded, last value wins. Never throws on junk. */
  public static Map<String, String> parseFormBody(String body) {
    Map<String, String> out = new LinkedHashMap<>();
    for (String pair : body.split("&", -1)) {
      if (pair.isEmpty()) {
        continue;
      }
      int eq = pair.indexOf('=');
      String k = eq < 0 ? pair : pair.substring(0, eq);
      String v = eq < 0 ? "" : pair.substring(eq + 1);
      out.put(unquote(k.replace('+', ' ')), unquote(v.replace('+', ' ')));
    }
    return out;
  }

  /**
   * Percent-decoding the way Python's urllib.parse.unquote does it: a valid %XX becomes its byte,
   * an invalid one stays as written, and the bytes are read as UTF-8 with replacement.
   */
  static String unquote(String s) {
    if (s.indexOf('%') < 0) {
      return s;
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(s.length());
    int i = 0;
    while (i < s.length()) {
      if (s.charAt(i) == '%' && i + 2 < s.length()) {
        int hi = Character.digit(s.charAt(i + 1), 16);
        int lo = Character.digit(s.charAt(i + 2), 16);
        if (hi >= 0 && lo >= 0) {
          bytes.write((hi << 4) | lo);
          i += 3;
          continue;
        }
      }
      int cp = s.codePointAt(i);
      byte[] raw = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
      bytes.write(raw, 0, raw.length);
      i += Character.charCount(cp);
    }
    return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
  }
}
