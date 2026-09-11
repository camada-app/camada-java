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

  private static final Pattern NAME_RE =
      Pattern.compile(
          "(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)",
          Pattern.CASE_INSENSITIVE);
  private static final Pattern JWT_RE =
      Pattern.compile("^eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}");
  private static final Pattern HEX_RE =
      Pattern.compile("^[a-f0-9]{32,}$", Pattern.CASE_INSENSITIVE);
  private static final Pattern B64_RE = Pattern.compile("^[A-Za-z0-9+/_-]{40,}={0,2}$");

  /** Additions only, never narrowing. */
  public static final List<String> REDACT_ALLOWLIST =
      List.of("plan", "role", "locale", "ab_variant");

  private static boolean suspectValue(String v) {
    return JWT_RE.matcher(v).find() || HEX_RE.matcher(v).find() || B64_RE.matcher(v).find();
  }

  /** Replaces credential-looking query values with ~r, preserving structure and order. */
  public static String scrubQuery(String query) {
    if (query == null || query.length() <= 1) {
      return query == null ? "" : query;
    }
    String lead = query.startsWith("?") ? "?" : "";
    List<String> out = new ArrayList<>();
    for (String p : (lead.isEmpty() ? query : query.substring(1)).split("&", -1)) {
      int eq = p.indexOf('=');
      if (eq < 0) {
        out.add(p);
        continue;
      }
      String name = p.substring(0, eq);
      String value = p.substring(eq + 1);
      out.add(NAME_RE.matcher(name).find() || suspectValue(value) ? name + "=~r" : p);
    }
    return lead + String.join("&", out);
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
  static String hmacSha256Hex(String key, String message) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return hex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e); // every JRE ships it
    }
  }

  static String hex(byte[] bytes) {
    char[] digits = "0123456789abcdef".toCharArray();
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      out[i * 2] = digits[(bytes[i] >> 4) & 0xF];
      out[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    return new String(out);
  }
}
