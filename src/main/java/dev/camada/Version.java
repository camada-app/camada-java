package dev.camada;

/**
 * The SDK's wire identity (SDK-03): {@code x-camada-sdk: <package>/<version>}. This literal is one
 * of two sources: pom.xml carries the same number directly after {@code
 * <artifactId>camada</artifactId>} (the sibling drift guards parse it there), and VersionTest
 * asserts the two agree. Plain X.Y.Z only, and @camada/java must stay in the analyst's SDK_NAMES:
 * its sdkId drops anything else.
 */
public final class Version {
  public static final String VERSION = "0.1.5";
  public static final String SDK_ID = "@camada/java/" + VERSION;

  private Version() {}
}
