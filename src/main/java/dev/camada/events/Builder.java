package dev.camada.events;

import dev.camada.Redact;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Wire-event builder: reproduces the collector's record() (edge-analyst
 * workers/collector/edge-collector.js) from a normalized request, so events are comparable across
 * taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.
 */
public final class Builder {
  private Builder() {}

  public static final List<String> HDRS =
      List.of(
          "accept",
          "accept-language",
          "accept-encoding",
          "sec-fetch-site",
          "sec-fetch-mode",
          "sec-fetch-dest",
          "sec-fetch-user",
          "sec-ch-ua",
          "sec-ch-ua-mobile",
          "sec-ch-ua-platform",
          "upgrade-insecure-requests",
          "dnt",
          "cache-control",
          "pragma",
          "referer",
          "origin",
          "cookie",
          "authorization",
          "x-requested-with",
          "content-type",
          "via",
          "x-forwarded-for",
          "priority",
          "sec-purpose",
          "save-data",
          "te",
          "if-modified-since",
          "if-none-match");
  private static final Map<String, Long> HDR_BIT = new HashMap<>();

  static {
    for (int i = 0; i < HDRS.size(); i++) {
      HDR_BIT.put(HDRS.get(i), 1L << i);
    }
  }

  // A schemeless header (`Authorization: <raw token>`) has no safe prefix: the first "word" IS
  // the credential. Only a real auth-scheme token followed by a space ever ships.
  private static final Pattern SCHEME_RE = Pattern.compile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,16}$");

  /**
   * A normalized request: {@code query} includes the leading '?' (or is empty), {@code headers} are
   * in the order the host gives them, {@code ip} is already resolved via the trusted-proxy config,
   * {@code httpVersion} is e.g. "1.1".
   */
  public record RequestInfo(
      String method,
      String host,
      String path,
      String query,
      List<Map.Entry<String, String>> headers,
      String ip,
      String httpVersion) {}

  public static String authScheme(String value) {
    if (value == null || value.isEmpty()) {
      return null;
    }
    int sp = value.indexOf(' ');
    if (sp <= 0) {
      return null;
    }
    String scheme = value.substring(0, sp);
    return SCHEME_RE.matcher(scheme).matches() ? scheme : null;
  }

  public static long nowMs() {
    return System.currentTimeMillis();
  }

  /** The mutable wire event; the caller fills st/dur on response-finish before enqueueing. */
  public static Map<String, Object> build(
      RequestInfo r, String tap, String rid, String sid, boolean newSession, String ja4) {
    long mask = 0;
    int hn = 0;
    int hb = 0;
    String cookie = "";
    List<String> names = new ArrayList<>();
    Map<String, String> first = new HashMap<>();
    if (r.headers() != null) {
      for (Map.Entry<String, String> h : r.headers()) {
        String name = h.getKey();
        String value = h.getValue() == null ? "" : h.getValue();
        String k = name.toLowerCase(Locale.ROOT);
        hn++;
        hb += name.length() + value.length();
        names.add(k);
        first.putIfAbsent(k, value);
        mask |= HDR_BIT.getOrDefault(k, 0L);
        if (k.equals("cookie")) {
          cookie = cookie.isEmpty() ? value : cookie + "; " + value;
        }
      }
    }
    String query = r.query() == null ? "" : r.query();
    int qn = 0;
    if (query.length() > 1) {
      for (String p : query.substring(1).split("&", -1)) {
        if (!p.isEmpty()) {
          qn++;
        }
      }
    }
    Map<String, Object> ev = new LinkedHashMap<>();
    ev.put("tap", tap);
    ev.put("rid", rid);
    ev.put("sid", sid);
    ev.put("ns", newSession ? 1 : 0);
    ev.put("ts", nowMs());
    ev.put("ip", r.ip());
    ev.put("proto", r.httpVersion() == null ? null : "HTTP/" + r.httpVersion());
    ev.put("m", r.method());
    ev.put("h", r.host());
    ev.put("p", r.path());
    ev.put("q", cap(Redact.scrubQuery(query), 512));
    ev.put("qn", qn);
    ev.put("ct", first.get("content-type"));
    ev.put("cl", first.get("content-length"));
    ev.put("ua", first.get("user-agent"));
    ev.put("chua", first.get("sec-ch-ua"));
    ev.put("chmob", first.get("sec-ch-ua-mobile"));
    ev.put("chplat", first.get("sec-ch-ua-platform"));
    ev.put("acc", first.get("accept"));
    ev.put("lang", first.get("accept-language"));
    ev.put("fs", first.get("sec-fetch-site"));
    ev.put("fm", first.get("sec-fetch-mode"));
    ev.put("fd", first.get("sec-fetch-dest"));
    ev.put("fu", first.get("sec-fetch-user"));
    ev.put("ref", first.get("referer"));
    ev.put("org", first.get("origin"));
    ev.put("xrw", first.get("x-requested-with"));
    ev.put("auth", authScheme(first.get("authorization"))); // scheme only, never the credential
    ev.put("hm", mask);
    ev.put("hn", hn);
    ev.put("hb", hb);
    ev.put("ck", cookie.isEmpty() ? 0 : cookie.split(";", -1).length);
    ev.put("hord", cap(String.join(",", names), 2048)); // header order as this host reports it
    if (ja4 != null && !ja4.isEmpty()) {
      ev.put("ja4", ja4);
    }
    ev.put("st", null);
    ev.put("dur", null); // 'dur': the collector wire already claims 'lat' for latitude
    return ev;
  }

  private static String cap(String s, int max) {
    return s.length() <= max ? s : s.substring(0, max);
  }
}
