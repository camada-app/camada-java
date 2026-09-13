package dev.camada;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * The first-party beacon (@camada/browser's dist/auto.global.js), vendored into the jar by
 * scripts/sync-beacon.sh as dev/camada/b.js + beacon.properties and loaded once here: served at
 * /_cam/b.js with no runtime file read. BeaconJsTest pins it to the sibling build byte for byte.
 */
public final class BeaconJs {
  private BeaconJs() {}

  public static final byte[] BYTES;
  public static final String JS;
  public static final String VERSION;
  public static final String SHA256;

  static {
    try (InputStream js = BeaconJs.class.getResourceAsStream("b.js");
        InputStream props = BeaconJs.class.getResourceAsStream("beacon.properties")) {
      if (js == null || props == null) {
        throw new IllegalStateException("camada: the vendored beacon is missing from the jar");
      }
      BYTES = js.readAllBytes();
      JS = new String(BYTES, StandardCharsets.UTF_8);
      Properties p = new Properties();
      p.load(props);
      VERSION = p.getProperty("version", "");
      SHA256 = p.getProperty("sha256", "");
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
