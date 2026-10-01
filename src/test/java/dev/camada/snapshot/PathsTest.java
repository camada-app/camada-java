package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

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
}
