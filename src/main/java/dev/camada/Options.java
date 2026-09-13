package dev.camada;

import java.util.Map;

/**
 * Engine options; everything credential-shaped comes from the environment. Mirrors the keyword
 * arguments of camada-python's Camada(...): the env map, the transport, a pinned refresh cadence,
 * the challenge switch and path, the snapshot version and the beacon paths.
 */
public final class Options {
  private Map<String, String> env;
  private Transport transport;
  private Double refreshS;
  private boolean challenge = true;
  private String challengePath = Constants.CHALLENGE_PATH;
  private int snapshotVersion = Constants.DEFAULT_SNAPSHOT_VERSION;
  private String scriptPath = Constants.SCRIPT_PATH;
  private String fpPath = Constants.FP_PATH;

  /** Where CAMADA_* are read from; defaults to {@code System.getenv()}. */
  public Options env(Map<String, String> env) {
    this.env = env;
    return this;
  }

  /** The HTTP seam that reaches the analyst (tests inject a fake); defaults to HttpTransport. */
  public Options transport(Transport transport) {
    this.transport = transport;
    return this;
  }

  /** Poll cadence in seconds; set, it is pinned (the server's poll_seconds no longer steers it). */
  public Options refreshS(double seconds) {
    this.refreshS = seconds;
    return this;
  }

  /**
   * Serve the proof-of-work page for challenge verdicts (CAMADA_CHALLENGE=0 also switches it off).
   */
  public Options challenge(boolean on) {
    this.challenge = on;
    return this;
  }

  /** Where the challenge page posts its solution. */
  public Options challengePath(String path) {
    this.challengePath = path;
    return this;
  }

  /** 5 (default) carries the custom rules; 4 drops them; 3 the allow/challenge sides too. */
  public Options snapshotVersion(int v) {
    this.snapshotVersion = v;
    return this;
  }

  /** The beacon script path; keep it in one directory with {@link #fpPath}. */
  public Options scriptPath(String path) {
    this.scriptPath = path;
    return this;
  }

  /** The beacon relay path. */
  public Options fpPath(String path) {
    this.fpPath = path;
    return this;
  }

  public Map<String, String> env() {
    return env;
  }

  public Transport transport() {
    return transport;
  }

  public Double refreshS() {
    return refreshS;
  }

  public boolean challenge() {
    return challenge;
  }

  public String challengePath() {
    return challengePath;
  }

  public int snapshotVersion() {
    return snapshotVersion;
  }

  public String scriptPath() {
    return scriptPath;
  }

  public String fpPath() {
    return fpPath;
  }
}
