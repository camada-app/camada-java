package dev.camada;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme only,
 * events/Builder), body field values (shape only), query params that look like credentials, or raw
 * user identifiers (HMAC-hashed here, inside the SDK, before anything reaches the queue). Ported
 * from {@code @camada/core} src/redact.ts.
 */
public final class Redact {
  private Redact() {}

  // Exact patterns of C6 v3. NAME_RE runs on ASCII-lowercased text (nameHit), so no case folding at
  // all; hex/b64 use matches() (whole string, \z semantics: no match before a trailing newline);
  // jwt is a prefix test (lookingAt). Classes are explicit ASCII.
  private static final Pattern NAME_RE =
      Pattern.compile(
          "(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)");
  private static final Pattern JWT_RE = Pattern.compile("eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}");
  private static final Pattern HEX_RE = Pattern.compile("[a-fA-F0-9]{32,}");
  private static final Pattern B64_RE = Pattern.compile("[A-Za-z0-9+/_-]{40,}={0,2}");

  /** Additions only, never narrowing. */
  public static final List<String> REDACT_ALLOWLIST =
      List.of("plan", "role", "locale", "ab_variant");

  private static boolean suspectValue(String v) {
    return JWT_RE.matcher(v).lookingAt()
        || HEX_RE.matcher(v).matches()
        || B64_RE.matcher(v).matches();
  }

  /** Lowercase A-Z only, then a substring search: ASCII-only case folding by construction. */
  private static boolean nameHit(String n) {
    char[] c = n.toCharArray();
    for (int i = 0; i < c.length; i++) {
      if (c[i] >= 'A' && c[i] <= 'Z') {
        c[i] = (char) (c[i] + 32);
      }
    }
    return NAME_RE.matcher(new String(c)).find();
  }

  private static int hexVal(char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1; // ASCII hex only: Character.digit would accept other scripts' digits
  }

  private static boolean hasEscape(String s) {
    for (int i = s.indexOf('%'); i >= 0 && i + 2 < s.length(); i = s.indexOf('%', i + 1)) {
      if (hexVal(s.charAt(i + 1)) >= 0 && hexVal(s.charAt(i + 2)) >= 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Percent-decoding that never throws: each {@code %HH} (ASCII hex) becomes the char with that
   * byte's value (Latin-1), any other {@code %} stays, {@code +} stays. Up to 4 passes; text still
   * holding a {@code %HH} after them is null (scrubbed). Never URLDecoder. Only ever used to TEST.
   */
  static String decode(String s) {
    for (int pass = 0; pass < 4 && hasEscape(s); pass++) {
      StringBuilder b = new StringBuilder(s.length());
      int i = 0;
      while (i < s.length()) {
        char c = s.charAt(i);
        int hi;
        int lo;
        if (c == '%'
            && i + 2 < s.length()
            && (hi = hexVal(s.charAt(i + 1))) >= 0
            && (lo = hexVal(s.charAt(i + 2))) >= 0) {
          b.append((char) (hi * 16 + lo));
          i += 3;
        } else {
          b.append(c);
          i++;
        }
      }
      s = b.toString();
    }
    return hasEscape(s) ? null : s;
  }

  /** One `name=value` or bare segment of a decoded nested value: a credential? */
  private static boolean credSegment(String seg) {
    int eq = seg.indexOf('=');
    return eq < 0
        ? suspectValue(seg)
        : nameHit(seg.substring(0, eq)) || suspectValue(seg.substring(eq + 1));
  }

  /**
   * A decoded value carrying {@code ?}, {@code &} or {@code =} is a credential when one of its
   * {@code [?&]} segments is (C6 v3). No further decoding, no recursion.
   */
  private static boolean nestedCred(String d) {
    if (d.indexOf('?') < 0 && d.indexOf('&') < 0 && d.indexOf('=') < 0) {
      return false;
    }
    for (String seg : d.split("[?&]", -1)) {
      if (credSegment(seg)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The
   * string is split on {@code &}, never URL-parsed. Each part's name and value are percent-decoded
   * before testing. {@code name=value} → {@code name=~r} when the name looks like a credential, the
   * value looks like one, or the value holds a nested query with a credential segment (replaced
   * whole, so payloads like {@code q=1' or '1'='1} stay visible to the scorer). A bare part →
   * {@code ~r} when it looks like a credential value or holds a credential segment. Either half
   * still encoded after 4 decode passes counts as a credential. The output keeps the raw text.
   */
  public static String scrubQuery(String query) {
    if (query == null || query.length() <= 1) {
      return query == null ? "" : query;
    }
    String lead = query.startsWith("?") ? "?" : "";
    List<String> out = new ArrayList<>();
    for (String p : (lead.isEmpty() ? query : query.substring(1)).split("&", -1)) {
      int eq = p.indexOf('=');
      if (eq < 0) {
        String d = decode(p);
        out.add(d == null || suspectValue(d) || nestedCred(d) ? "~r" : p);
        continue;
      }
      String name = p.substring(0, eq);
      String dn = decode(name);
      String dv = decode(p.substring(eq + 1));
      out.add(
          dn == null || dv == null || nameHit(dn) || suspectValue(dv) || nestedCred(dv)
              ? name + "=~r"
              : p);
    }
    return lead + String.join("&", out);
  }

  /**
   * A URL (a Referer) with its query and fragment run through scrubQuery (camada-all-ijsa); the
   * scheme, host and path are kept as they are. The path gets the same treatment as the request's
   * own path {@code p} (none): a same-origin Referer's path already shipped as {@code p} on that
   * page's own event, and a cross-origin one carries only the origin under the browsers' default
   * policy.
   */
  public static String scrubUrl(String url) {
    if (url == null) {
      return null;
    }
    int hash = url.indexOf('#');
    String head = hash < 0 ? url : url.substring(0, hash);
    int q = head.indexOf('?');
    String scrubbed = q < 0 ? head : head.substring(0, q) + scrubQuery(head.substring(q));
    return hash < 0 ? scrubbed : scrubbed + "#" + scrubQuery(url.substring(hash + 1));
  }

  /** Body shape only: field names and byte sizes, never values. One level deep. */
  public static Map<String, Integer> bodyShape(Object obj) {
    Map<String, Object> m = Json.asMap(obj);
    if (m == null) {
      return null;
    }
    Map<String, Integer> out = new LinkedHashMap<>();
    for (Map.Entry<String, Object> e : m.entrySet()) {
      Object v = e.getValue();
      int size;
      if (v instanceof String s) {
        size = s.length();
      } else if (v == null) {
        size = 0;
      } else {
        try {
          size = Json.stringify(v).length();
        } catch (RuntimeException err) {
          size = 0;
        }
      }
      out.put(e.getKey(), size);
    }
    return out;
  }

  /**
   * Stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so the hash can
   * never double as anything else, truncated to 32 hex chars. The raw identifier never leaves.
   */
  public static String hashUserId(String userId, String ingestToken) {
    return hmacSha256Hex(ingestToken, "uid:" + userId).substring(0, 32);
  }

  /** HMAC-SHA256 as lower-case hex; the one primitive the challenge kit shares with this file. */
  public static String hmacSha256Hex(String key, String message) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return hex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e); // every JRE ships it
    }
  }

  /** Lower-case hex, the way the wire spells digests (shared with the challenge kit). */
  public static String hex(byte[] bytes) {
    char[] digits = "0123456789abcdef".toCharArray();
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      out[i * 2] = digits[(bytes[i] >> 4) & 0xF];
      out[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    return new String(out);
  }
}
