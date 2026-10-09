package dev.camada;

/**
 * The SDK's wire identity (SDK-03): {@code x-camada-sdk: <package>/<version>}. This literal is one
 * of two sources: pom.xml carries the same number directly after {@code
 * <artifactId>camada</artifactId>} (the sibling drift guards parse it there), and VersionTest
 * asserts the two agree. Plain X.Y.Z only: the analyst's SDK_RE drops anything else.
 */
public final class Version {
  public static final String VERSION = "0.1.3";
  public static final String SDK_ID = "@camada/java/" + VERSION;

  private Version() {}
}
