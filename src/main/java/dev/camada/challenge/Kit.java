package dev.camada.challenge;

import dev.camada.Redact;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The challenge kit over the JDK's HMAC-SHA256 and SHA-256, ported from {@code @camada/core}
 * src/challenge/verify.ts. The hex and HMAC primitives are {@link Redact}'s: one copy in the SDK.
 */
public final class Kit {
  private final String secret;

  public Kit(String secret) {
    this.secret = secret;
  }

  /**
   * SHA-256 of a UTF-8 string as lower-case hex (the proof-of-work primitive, shared with tests).
   */
  public static String sha256Hex(String s) {
    try {
      return Redact.hex(
          MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e); // every JRE ships it
    }
  }

  private String hmac(String msg) {
    return Redact.hmacSha256Hex(secret, msg);
  }

  private String at(String ip, long day) {
    return hmac(Format.nonceMessage(ip, day)).substring(0, Format.NONCE_HEX);
  }

  /** Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored. */
  public String nonce(String ip, long nowMs) {
    return at(ip, Format.utcDay(nowMs));
  }

  /**
   * Yesterday still passes: a solve started before midnight UTC must not be thrown away. So one
   * solved (nonce, solution) pair is replayable from its own IP for up to ~48 h, minting a fresh 1
   * h cookie each time. That is the price of a stateless nonce (§D2) and it is deliberate — do not
   * "fix" it into something that needs shared server state.
   */
  public boolean nonceValid(String ip, long nowMs, String nonce) {
    if (ip == null || ip.isEmpty() || nonce == null || nonce.length() != Format.NONCE_HEX) {
      return false;
    }
    long day = Format.utcDay(nowMs);
    return Format.safeEqual(nonce, at(ip, day)) || Format.safeEqual(nonce, at(ip, day - 1));
  }

  public String issue(String ip, long nowMs) {
    long exp = nowMs + Format.CHALLENGE_TTL_MS;
    return exp + "." + hmac(Format.tokenMessage(ip, exp));
  }

  /**
   * A null ip is refused outright: without one the token is bound to nothing, so a single solve
   * would mint a cookie every other unidentified client could present. Adapters must fail open
   * (serve no challenge) rather than challenge a client they cannot identify.
   */
  public boolean tokenValid(String ip, long nowMs, String cookieValue) {
    if (ip == null || ip.isEmpty()) {
      return false;
    }
    Format.Token t = Format.splitToken(cookieValue);
    if (t == null) {
      return false;
    }
    if (t.exp() <= nowMs || t.exp() > nowMs + Format.CHALLENGE_TTL_MS) {
      return false;
    }
    return Format.safeEqual(t.mac(), hmac(Format.tokenMessage(ip, t.exp())));
  }

  /** Proof of work ONLY. Never call it without a passing nonceValid() for the same nonce. */
  public boolean solutionOk(String nonce, String solution) {
    return Format.solutionShapeOk(solution)
        && Format.powOk(sha256Hex(nonce + "." + solution), Format.POW_BITS);
  }

  /** The whole submission: the nonce is ours and unexpired, and the work is done. */
  public boolean verify(String ip, long nowMs, String nonce, String solution) {
    return nonceValid(ip, nowMs, nonce) && solutionOk(nonce == null ? "" : nonce, solution);
  }
}
