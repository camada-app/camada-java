package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import dev.camada.Config.TrustedProxy;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer: raw
 * X-Forwarded-For is attacker-writable and never trusted without explicit configuration.
 */
class IpTest {
  static TrustedProxy hops(int n) {
    return new TrustedProxy("hops", n, List.of());
  }

  @Test
  void socketPeerWithoutConfigEvenWhenXffIsPresent() {
    assertEquals("10.0.0.1", Ip.resolveClientIp("10.0.0.1", "203.0.113.66", null));
    assertEquals(
        "10.0.0.1",
        Ip.resolveClientIp("10.0.0.1", "203.0.113.66", new TrustedProxy("none", 0, List.of())));
  }

  @Test
  void v4MappedPeerIsUnwrapped() {
    assertEquals("10.0.0.1", Ip.resolveClientIp("::ffff:10.0.0.1", null, null));
    assertNull(Ip.resolveClientIp(null, "1.2.3.4", null));
  }

  @Test
  void hopsCountsFromTheRight() {
    assertEquals(
        "198.51.100.7", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 198.51.100.7", hops(1)));
    assertEquals(
        "203.0.113.66", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 198.51.100.7", hops(2)));
    // out of range: the peer
    assertEquals("10.0.0.1", Ip.resolveClientIp("10.0.0.1", "203.0.113.66", hops(2)));
  }

  @Test
  void vercelTakesTheRightmostEntry() {
    assertEquals(
        "203.0.113.66",
        Ip.resolveClientIp(
            "10.0.0.1", "spoof, 203.0.113.66", new TrustedProxy("vercel", 0, List.of())));
  }

  @Test
  void cidrsSkipsTrustedProxiesFromTheRight() {
    TrustedProxy cfg = new TrustedProxy("cidrs", 0, List.of("10.0.0.0/8", "2001:db8::/32"));
    assertEquals(
        "203.0.113.66", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 10.1.2.3, 10.9.9.9", cfg));
    assertEquals("203.0.113.66", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 2001:db8::5", cfg));
    // everything trusted: the peer
    assertEquals("10.0.0.1", Ip.resolveClientIp("10.0.0.1", "10.1.2.3", cfg));
    // candidate must parse
    assertEquals("10.0.0.1", Ip.resolveClientIp("10.0.0.1", "not-an-ip, 10.1.2.3", cfg));
    // a cidr that does not parse trusts nothing
    TrustedProxy junk = new TrustedProxy("cidrs", 0, List.of("nope", "10.0.0.0/99", "::1/129"));
    assertEquals("10.1.2.3", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 10.1.2.3", junk));
  }

  @Test
  void envStringForms() {
    assertNull(Config.parseTrustedProxyEnv(null));
    assertEquals(new TrustedProxy("none", 0, List.of()), Config.parseTrustedProxyEnv("none"));
    assertEquals(new TrustedProxy("vercel", 0, List.of()), Config.parseTrustedProxyEnv("vercel"));
    assertEquals(hops(2), Config.parseTrustedProxyEnv("hops:2"));
    assertNull(Config.parseTrustedProxyEnv("hops:0"));
    assertNull(Config.parseTrustedProxyEnv("hops:x"));
    assertEquals(
        new TrustedProxy("cidrs", 0, List.of("10.0.0.0/8", "192.0.2.0/24")),
        Config.parseTrustedProxyEnv("cidrs:10.0.0.0/8, 192.0.2.0/24"));
    assertNull(Config.parseTrustedProxyEnv("cidrs:"));
    assertNull(Config.parseTrustedProxyEnv("bogus"));
  }
}
