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
    assertEquals("10.1.2.3", Ip.resolveClientIp(null, "203.0.113.66, 10.1.2.3", junk));
    // ... not even the peer
    assertEquals("10.0.0.1", Ip.resolveClientIp("10.0.0.1", "203.0.113.66, 10.1.2.3", junk));
  }

  /** The Cloudflare preset as the dashboard stores it (the 22 published ranges). */
  static final List<String> CF =
      List.of(
          "173.245.48.0/20",
          "103.21.244.0/22",
          "103.22.200.0/22",
          "103.31.4.0/22",
          "141.101.64.0/18",
          "108.162.192.0/18",
          "190.93.240.0/20",
          "188.114.96.0/20",
          "197.234.240.0/22",
          "198.41.128.0/17",
          "162.158.0.0/15",
          "104.16.0.0/13",
          "104.24.0.0/14",
          "172.64.0.0/13",
          "131.0.72.0/22",
          "2400:cb00::/32",
          "2606:4700::/32",
          "2803:f800::/32",
          "2405:b500::/32",
          "2405:8100::/32",
          "2a06:98c0::/29",
          "2c0f:f248::/32");

  @Test
  void trialsightsShapeResolvesToTheClient() {
    // camada-all-yfc6 Director triage: App Engine's local front end is the socket peer
    // (127.0.0.1) and Google appends 169.254.1.1 after the Cloudflare edge.
    List<String> cidrs = new java.util.ArrayList<>(CF);
    cidrs.add("169.254.0.0/16");
    TrustedProxy cfg = new TrustedProxy("cidrs", 0, cidrs);
    assertEquals(
        "198.51.100.9",
        Ip.resolveClientIp("127.0.0.1", "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", cfg));
    // a direct appspot hit
    assertEquals(
        "198.51.100.9", Ip.resolveClientIp("127.0.0.1", "6.6.6.6, 198.51.100.9, 169.254.1.1", cfg));
    assertEquals(
        "198.51.100.9",
        Ip.resolveClientIp(
            "::ffff:127.0.0.1", "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", cfg));
  }

  @Test
  void cidrsDirectHitIgnoresAForgedXff() {
    // camada-all-yfc6: a peer outside every trusted range did not come through a proxy
    TrustedProxy cfg = new TrustedProxy("cidrs", 0, CF);
    assertEquals("203.0.113.200", Ip.resolveClientIp("203.0.113.200", "203.0.113.66", cfg));
    assertEquals("203.0.113.200", Ip.resolveClientIp("203.0.113.200", "8.8.8.8", cfg));
    assertEquals("203.0.113.200", Ip.resolveClientIp("203.0.113.200", "8.8.8.8, 172.64.1.1", cfg));
    assertEquals("203.0.113.200", Ip.resolveClientIp("::FFFF:203.0.113.200", "8.8.8.8", cfg));
    // through the edge: unchanged
    assertEquals("198.51.100.9", Ip.resolveClientIp("172.64.1.1", "1.2.3.4, 198.51.100.9", cfg));
    // no peer: the plain walk
    assertEquals(
        "198.51.100.9", Ip.resolveClientIp(null, "1.2.3.4, 198.51.100.9, 172.64.1.1", cfg));
    // loopback is trusted only as the peer
    assertEquals("127.0.0.1", Ip.resolveClientIp("172.64.1.1", "127.0.0.1", cfg));
  }

  @Test
  void xffEntriesWithAPortResolveToTheAddress() {
    // camada-all-0vho: Azure Application Gateway writes ip:port
    assertEquals(
        "203.0.113.66", Ip.resolveClientIp("169.254.130.1", "203.0.113.66:51234", hops(1)));
    assertEquals(
        "2001:db8::66", Ip.resolveClientIp("169.254.130.1", "[2001:db8::66]:51234", hops(1)));
    // a bare v6 is never split
    assertEquals(
        "2001:db8::66:8080", Ip.resolveClientIp("169.254.130.1", "2001:db8::66:8080", hops(1)));
    assertEquals(
        "203.0.113.66",
        Ip.resolveClientIp(
            "169.254.130.1",
            "203.0.113.66, 169.254.1.1:5000",
            new TrustedProxy("cidrs", 0, List.of("169.254.0.0/16"))));
    // malformed: the peer
    assertEquals(
        "169.254.130.1", Ip.resolveClientIp("169.254.130.1", "203.0.113.66:80:90", hops(1)));
    assertEquals(
        "169.254.130.1", Ip.resolveClientIp("169.254.130.1", "[203.0.113.66]:80", hops(1)));
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
