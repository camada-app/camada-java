package dev.camada;

/**
 * Allocation-free IP parsers, ported 1:1 from edge-analyst src/blocklist.js through
 * {@code @camada/core} src/snapshot/ipparse.ts (the reference the conformance fixtures are
 * generated from). Behaviour must not drift: ip4 returns -1 on anything unusual; ip6 rejects zone
 * ids and v4-mapped forms. Java ints are signed, so the v4 value comes back as a long (0..2^32-1,
 * or -1) and the v6 words as four ints the matcher compares unsigned.
 */
public final class IpParse {
  private IpParse() {}

  /**
   * Dotted-quad IPv4 to a uint32 (as a long), or -1 when the string is not a plain IPv4 address.
   */
  public static long parseIp4(String s) {
    long n = 0;
    int part = 0;
    int digits = 0;
    int dots = 0;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      if (ch == '.') {
        if (digits == 0 || part > 255) {
          return -1;
        }
        dots++;
        if (dots > 3) {
          return -1;
        }
        n = n * 256 + part;
        part = 0;
        digits = 0;
      } else if (ch >= '0' && ch <= '9') {
        part = part * 10 + (ch - '0');
        digits++;
        if (digits > 3) {
          return -1;
        }
      } else {
        return -1;
      }
    }
    if (dots != 3 || digits == 0 || part > 255) {
      return -1;
    }
    return n * 256 + part;
  }

  /** IPv6 text to four big-endian uint32 words, or null when it is not a plain IPv6 address. */
  public static int[] parseIp6(String s) {
    int length = s.length();
    int[] groups = new int[8];
    int n = 0;
    int val = 0;
    int digits = 0;
    int dbl = -1;
    int i = 0;
    if (length > 1 && s.charAt(0) == ':' && s.charAt(1) == ':') {
      dbl = 0;
      i = 2;
    }
    while (i <= length) {
      char c = i < length ? s.charAt(i) : ':'; // a sentinel colon closes the last group
      if (c == ':') {
        if (digits > 0) {
          if (n >= 8) {
            return null;
          }
          groups[n++] = val;
          val = 0;
          digits = 0;
        } else if (i < length) {
          if (dbl != -1) {
            return null;
          }
          dbl = n;
        }
      } else {
        int d;
        if (c >= '0' && c <= '9') {
          d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
          d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
          d = c - 'A' + 10;
        } else {
          return null;
        }
        val = (val << 4) | d;
        digits++;
        if (digits > 4) {
          return null;
        }
      }
      i++;
    }
    if (dbl == -1) {
      if (n != 8) {
        return null;
      }
    } else {
      if (n >= 8) {
        return null;
      }
      int shift = 8 - n;
      for (int k = 7; k >= dbl + shift; k--) {
        groups[k] = groups[k - shift];
      }
      for (int k = dbl; k < dbl + shift; k++) {
        groups[k] = 0;
      }
    }
    return new int[] {
      (groups[0] << 16) | groups[1],
      (groups[2] << 16) | groups[3],
      (groups[4] << 16) | groups[5],
      (groups[6] << 16) | groups[7],
    };
  }
}
