package dev.camada;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Configuration shapes shared by the client and the engine. {@link #parseKey} splits CAMADA_KEY,
 * and {@link RemoteConfig} is what GET /snapshot hands back in x-camada-config (whitelisted
 * server-side).
 */
public final class Config {
  private Config() {}

  /**
   * Mirrors the server-validated tenant config (edge-analyst src/tenant-config.js): {mode: none} |
   * {mode: hops, hops: N} | {mode: cidrs, cidrs: [...]} | {mode: vercel}.
   */
  public record TrustedProxy(String mode, int hops, List<String> cidrs) {
    public TrustedProxy {
      cidrs = cidrs == null ? List.of() : List.copyOf(cidrs);
    }
  }

  /** The parsed x-camada-config header; a null field is one the server did not send. */
  public record RemoteConfig(
      String tenant,
      Boolean beacon,
      Double sample,
      List<String> exclude,
      TrustedProxy trustedProxy,
      Double pollSeconds) {
    public RemoteConfig {
      exclude = exclude == null ? List.of() : List.copyOf(exclude);
    }
  }

  /**
   * CAMADA_KEY is {@code <ingest_token>.<snap_token>} (printed by reconcile instructions and seed).
   * Returns {ingest, snap}, or null.
   */
  public static String[] parseKey(String key) {
    if (key == null || key.isEmpty()) {
      return null;
    }
    int dot = key.indexOf('.');
    if (dot <= 0 || dot == key.length() - 1) {
      return null;
    }
    return new String[] {key.substring(0, dot), key.substring(dot + 1)};
  }

  /**
   * CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or malformed returns null,
   * which callers treat as "defer to the server-delivered tenant config", never as trust.
   */
  public static TrustedProxy parseTrustedProxyEnv(String v) {
    if (v == null || v.isEmpty()) {
      return null;
    }
    if (v.equals("none")) {
      return new TrustedProxy("none", 0, List.of());
    }
    if (v.equals("vercel")) {
      return new TrustedProxy("vercel", 0, List.of());
    }
    if (v.startsWith("hops:")) {
      int hops;
      try {
        hops = Integer.parseInt(v.substring(5).trim());
      } catch (NumberFormatException e) {
        return null;
      }
      return hops >= 1 ? new TrustedProxy("hops", hops, List.of()) : null;
    }
    if (v.startsWith("cidrs:")) {
      List<String> cidrs = new ArrayList<>();
      for (String c : v.substring(6).split(",")) {
        if (!c.trim().isEmpty()) {
          cidrs.add(c.trim());
        }
      }
      return cidrs.isEmpty() ? null : new TrustedProxy("cidrs", 0, cidrs);
    }
    return null;
  }

  /** The parsed x-camada-config header; anything but a JSON object is ignored (previous kept). */
  public static RemoteConfig remoteConfig(Object raw) {
    Map<String, Object> m = Json.asMap(raw);
    if (m == null) {
      return null;
    }
    Object tenant = m.get("tenant");
    Object beacon = m.get("beacon");
    return new RemoteConfig(
        tenant instanceof String s ? s : null,
        beacon instanceof Boolean b ? b : null,
        number(m.get("sample")),
        strings(m.get("exclude")),
        trustedProxy(Json.asMap(m.get("trusted_proxy"))),
        number(m.get("poll_seconds")));
  }

  /**
   * The server's trusted_proxy object; a shape it would never send reads as absent, never as trust.
   */
  static TrustedProxy trustedProxy(Map<String, Object> m) {
    if (m == null || !(m.get("mode") instanceof String mode)) {
      return null;
    }
    switch (mode) {
      case "none":
      case "vercel":
        return new TrustedProxy(mode, 0, List.of());
      case "hops":
        Double hops = number(m.get("hops"));
        return hops == null ? null : new TrustedProxy("hops", (int) hops.doubleValue(), List.of());
      case "cidrs":
        return new TrustedProxy("cidrs", 0, strings(m.get("cidrs")));
      default:
        return null;
    }
  }

  public static Double number(Object v) {
    return v instanceof Number n ? n.doubleValue() : null;
  }

  /**
   * The strings of a JSON list (anything else in it is skipped); an absent or non-list is empty.
   */
  public static List<String> strings(Object v) {
    List<String> out = new ArrayList<>();
    if (v instanceof List<?> l) {
      for (Object o : l) {
        if (o instanceof String s) {
          out.add(s);
        }
      }
    }
    return out;
  }
}
