package dev.camada;

import dev.camada.Config.TrustedProxy;
import java.util.Map;

/**
 * Environment wiring. The two-line quickstart depends on this doing the right thing:
 *
 * <pre>
 *   CAMADA_KEY=&lt;ingest_token&gt;.&lt;snap_token&gt;   (printed by `reconcile instructions` and seed)
 *   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
 *   CAMADA_DISABLED=1                        kill switch, checked at boot and per request
 *   CAMADA_SERVERLESS=1                      lazy snapshot mode (no poll thread)
 *   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
 *   CAMADA_CHALLENGE=0                       do not enforce challenge verdicts
 * </pre>
 *
 * {@code secret} is the HMAC key for the challenge nonce/cookie — it never leaves the process.
 * {@code trustedProxy} null = defer to the server-delivered config.
 */
public record Env(
    String ingestToken,
    String snapToken,
    String secret,
    String ingestUrl,
    String snapshotUrl,
    boolean serverless,
    TrustedProxy trustedProxy) {

  /**
   * PLACEHOLDER default, the same one {@code @camada/node} and camada-python carry — confirm the
   * production ingest domain before any Maven Central publish.
   */
  public static final String DEFAULT_INGEST_URL = "https://in.camada.dev";

  /** Null (SDK stays inert, one log line) rather than throwing on bad config. */
  public static Env resolve(Map<String, String> env) {
    String[] key = Config.parseKey(env.get("CAMADA_KEY"));
    String ingestToken = key != null ? key[0] : env.get("CAMADA_TOKEN");
    String snapToken = key != null ? key[1] : env.get("CAMADA_SNAPSHOT_TOKEN");
    if (ingestToken == null || ingestToken.isEmpty() || snapToken == null || snapToken.isEmpty()) {
      return null;
    }
    String ingestUrl = blankToNull(env.get("CAMADA_INGEST_URL"));
    if (ingestUrl == null) {
      ingestUrl = DEFAULT_INGEST_URL;
    }
    while (ingestUrl.endsWith("/")) {
      ingestUrl = ingestUrl.substring(0, ingestUrl.length() - 1);
    }
    String snapshotUrl = blankToNull(env.get("CAMADA_SNAPSHOT_URL"));
    String rawKey = blankToNull(env.get("CAMADA_KEY"));
    return new Env(
        ingestToken,
        snapToken,
        rawKey != null ? rawKey : ingestToken + "." + snapToken,
        ingestUrl,
        snapshotUrl != null ? snapshotUrl : ingestUrl + "/snapshot",
        "1".equals(env.get("CAMADA_SERVERLESS")),
        Config.parseTrustedProxyEnv(env.get("CAMADA_TRUSTED_PROXY")));
  }

  private static String blankToNull(String s) {
    return s == null || s.isEmpty() ? null : s;
  }
}
