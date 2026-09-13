package dev.camada;

import java.util.function.IntConsumer;

/**
 * Run the app. {@code rid}/{@code setCookie} ride the response; {@code ctx} is stored on the host
 * request (the "camada" attribute); {@code onFinish(status)} is called once at the end. {@link
 * #INERT} is the do-nothing answer: nothing stamped, nothing shipped.
 */
public record Passed(String rid, String setCookie, Context ctx, IntConsumer onFinish)
    implements Result {
  public static final Passed INERT = new Passed(null, null, null, null);
}
