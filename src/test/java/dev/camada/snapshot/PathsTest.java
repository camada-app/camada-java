package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/**
 * Spellings the golden fixtures do not carry, pinned to edge-analyst src/blocklist.js pathForms.
 */
class PathsTest {
  @Test
  void formsMatchTheReference() {
    String[][] cases = {
      {"/", "/", "/", "/"},
      {"//a//b/", "//a//b/", "/a/b", "/a/b"},
      {"/x/%2e%2E/y", "/x/%2e%2E/y", "/x/../y", "/y"},
      {"/..;/admin", "/..;/admin", "/../admin", "/admin"},
      {"/a%2Fb", "/a%2Fb", "/a%2fb", "/a%2fb"},
      {"/caf%C3%A9", "/caf%C3%A9", "/caf%c3%a9", "/caf%c3%a9"},
      {"/café", "/café", "/caf%c3%a9", "/caf%c3%a9"},
      {"/a b", "/a b", "/a%20b", "/a%20b"},
      {"/%", "/%", "/%25", "/%25"},
      {"/%zz", "/%zz", "/%25zz", "/%25zz"},
      {"/a#b?c", "/a", "/a", "/a"},
      {"/..", "/..", "/..", "/"},
    };
    for (String[] c : cases) {
      assertArrayEquals(new String[] {c[1], c[2], c[3]}, Paths.forms(c[0]), c[0]);
    }
  }

  @Test
  void rawFormEncodesControlsAsLowerHex() {
    assertArrayEquals(new String[] {"/a%0a%7f", "/a%0a%7f", "/a%0a%7f"}, Paths.forms("/a\n\u007f"));
  }

  @Test
  void hitTriesARepeatedFormOnce() {
    int[] n = {0};
    Predicate<String> no = p -> ++n[0] < 0;
    Predicate<String> yes = p -> ++n[0] > 0;
    String[] same = Paths.forms("/a/b");
    String[] three = {"/a", "/b", "/c"};
    String[] repeat = {"/a", "/b", "/b"};
    assertFalse(Paths.hit(no, same, true));
    assertEquals(1, n[0]);
    n[0] = 0;
    assertTrue(Paths.hit(yes, same, false));
    assertEquals(1, n[0]);
    n[0] = 0;
    assertFalse(Paths.hit(no, same, false));
    assertEquals(1, n[0]);
    n[0] = 0;
    assertFalse(Paths.hit(no, three, true));
    assertEquals(3, n[0]);
    n[0] = 0;
    assertFalse(Paths.hit(no, repeat, true));
    assertEquals(2, n[0]);
    n[0] = 0;
    assertFalse(Paths.hit(no, three, false));
    assertEquals(1, n[0]);
    assertTrue(Paths.hit(p -> p.equals("/c"), three, true));
    assertTrue(Paths.hit(p -> p.equals("/b"), repeat, true));
    assertFalse(Paths.hit(p -> p.equals("/b"), three, false));
    assertTrue(Paths.hit(p -> !p.equals("/a"), three, false));
  }
}
