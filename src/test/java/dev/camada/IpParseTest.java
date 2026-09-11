package dev.camada;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Ported from the reference edge-analyst src/blocklist.js parsers: ip4 returns -1 on anything
 * unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.
 */
class IpParseTest {
  @Test
  void ip4DottedQuadToInt() {
    assertEquals((203L << 24) | (113L << 8) | 66L, IpParse.parseIp4("203.0.113.66"));
    assertEquals(0xFFFFFFFFL, IpParse.parseIp4("255.255.255.255"));
    assertEquals(0L, IpParse.parseIp4("0.0.0.0"));
  }

  @Test
  void ip4RejectsAnythingUnusual() {
    for (String bad :
        new String[] {
          "",
          "1.2.3",
          "1.2.3.4.5",
          "256.1.1.1",
          "1..2.3",
          "01.2.3.4444",
          "a.b.c.d",
          " 1.2.3.4",
          "1.2.3.4\n"
        }) {
      assertEquals(-1L, IpParse.parseIp4(bad), bad);
    }
  }

  @Test
  void ip6FullAndCompressedForms() {
    assertArrayEquals(new int[] {0x20010DB8, 0, 0, 1}, IpParse.parseIp6("2001:db8::1"));
    assertArrayEquals(new int[] {0, 0, 0, 1}, IpParse.parseIp6("::1"));
    assertArrayEquals(new int[] {0, 0, 0, 0}, IpParse.parseIp6("::"));
    assertArrayEquals(new int[] {0xFE800000, 0, 0, 1}, IpParse.parseIp6("fe80:0:0:0:0:0:0:1"));
    assertArrayEquals(
        new int[] {0x20010DB8, 0xCAFE0000, 0, 0}, IpParse.parseIp6("2001:DB8:CAFE::"));
  }

  @Test
  void ip6RejectsZoneIdsMappedV4AndMalformed() {
    for (String bad :
        new String[] {
          "fe80::1%eth0",
          "::ffff:1.2.3.4",
          "1:2:3:4:5:6:7:8:9",
          "1::2::3",
          "12345::",
          "g::1",
          "1:2:3:4:5:6:7",
          ":1::"
        }) {
      assertNull(IpParse.parseIp6(bad), bad);
    }
  }
}
