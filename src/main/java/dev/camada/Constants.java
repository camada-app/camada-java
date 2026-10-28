package dev.camada;

import java.util.Set;

/** The SDK's fixed wire and path constants; the Java twin of camada-python's constants.py. */
public final class Constants {
  private Constants() {}

  /**
   * Tap identifier this SDK claims on the wire. The server validates against its own enum and
   * decides itself what each tap can see: an SDK can never grant itself more than that, only name
   * its position — and an unknown name is silently read as a proxy, so this literal is
   * load-bearing.
   */
  public static final String TAP = "sdk-java";

  public static final double DEFAULT_REFRESH_S = 30.0;

  /**
   * 5 carries the tenant's ordered custom rules (§D3); a tenant without one is answered with the
   * next container down.
   */
  public static final int DEFAULT_SNAPSHOT_VERSION = 5;

  public static final String KILL_SWITCH_ENV = "CAMADA_DISABLED";

  public static final String SCRIPT_PATH = "/_cam/b.js";
  public static final String FP_PATH = "/_cam/fp";

  /** Matches the server's /fp cap: never accept what ingest will 413. */
  public static final int FP_MAX = 32 * 1024;

  // Row keys only the SDK can attest (TLS/network facts, outcome, session, track()). A beacon
  // body is the visitor's, so these never ride a sig:1 row; the analyst joins them from the
  // beacon's request row.
  static final Set<String> REQUEST_ROW_KEYS =
      Set.of(
          "tlsx", "ja4", "asn", "cc", "sid", "ns", "st", "dur", "rt", "blk", "rl", "wrn", "chs",
          "ch", "et", "uid");

  public static final String CHALLENGE_PATH = "/__camada/challenge";

  /** The verify form is ~120 bytes; anything larger is not ours. */
  public static final int BODY_MAX = 4 * 1024;

  /** Same cookie as the edge collector: sid/ns comparable across taps. */
  public static final String SESSION_COOKIE = "_sfp";

  /** 30 days. */
  public static final int SESSION_MAX_AGE = 2592000;
}
