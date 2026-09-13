package dev.camada;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The minimal JSON the SDK needs and the JDK does not ship: snapshot meta, x-camada-config, the
 * event batches and the beacon body. Objects parse to insertion-ordered maps, integers to Long,
 * every other number to Double (NaN and 1e999 included, as Python's json admits them — the config
 * reader guards against them), junk throws IllegalArgumentException — as does nesting past {@link
 * #MAX_DEPTH}: the parser recurses per level, and a 32 KB beacon body of '[' must be a dropped
 * body, not a StackOverflowError on the request thread. No runtime dependency.
 */
public final class Json {
  private Json() {}

  /** Nesting the parser accepts; nothing on the wire goes past a handful of levels. */
  public static final int MAX_DEPTH = 512;

  /** The object behind a parsed value, or null when it is not a JSON object. */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> asMap(Object v) {
    return v instanceof Map<?, ?> ? (Map<String, Object>) v : null;
  }

  public static Object parse(String text) {
    Parser p = new Parser(text);
    p.skipWs();
    Object v = p.value();
    p.skipWs();
    if (p.i != text.length()) {
      throw p.error("trailing characters");
    }
    return v;
  }

  private static final class Parser {
    final String s;
    int i;
    int depth;

    Parser(String s) {
      this.s = s;
    }

    IllegalArgumentException error(String what) {
      return new IllegalArgumentException("camada: bad JSON, " + what + " at " + i);
    }

    void skipWs() {
      while (i < s.length()) {
        char c = s.charAt(i);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          i++;
        } else {
          break;
        }
      }
    }

    char peek() {
      if (i >= s.length()) {
        throw error("unexpected end");
      }
      return s.charAt(i);
    }

    void expect(char c) {
      if (peek() != c) {
        throw error("expected '" + c + "'");
      }
      i++;
    }

    Object value() {
      char c = peek();
      switch (c) {
        case '{':
          return object();
        case '[':
          return array();
        case '"':
          return string();
        case 't':
          literal("true");
          return Boolean.TRUE;
        case 'f':
          literal("false");
          return Boolean.FALSE;
        case 'n':
          literal("null");
          return null;
        case 'N':
          literal("NaN");
          return Double.NaN;
        case 'I':
          literal("Infinity");
          return Double.POSITIVE_INFINITY;
        default:
          if (c == '-' || (c >= '0' && c <= '9')) {
            return number();
          }
          throw error("unexpected '" + c + "'");
      }
    }

    void literal(String word) {
      if (!s.startsWith(word, i)) {
        throw error("bad literal");
      }
      i += word.length();
    }

    void descend() {
      if (++depth > MAX_DEPTH) {
        throw error("nesting deeper than " + MAX_DEPTH);
      }
    }

    Map<String, Object> object() {
      expect('{');
      descend();
      Map<String, Object> out = new LinkedHashMap<>();
      skipWs();
      if (peek() == '}') {
        i++;
        depth--;
        return out;
      }
      while (true) {
        skipWs();
        String key = string();
        skipWs();
        expect(':');
        skipWs();
        out.put(key, value());
        skipWs();
        char c = peek();
        i++;
        if (c == '}') {
          depth--;
          return out;
        }
        if (c != ',') {
          throw error("expected ',' or '}'");
        }
      }
    }

    List<Object> array() {
      expect('[');
      descend();
      List<Object> out = new ArrayList<>();
      skipWs();
      if (peek() == ']') {
        i++;
        depth--;
        return out;
      }
      while (true) {
        skipWs();
        out.add(value());
        skipWs();
        char c = peek();
        i++;
        if (c == ']') {
          depth--;
          return out;
        }
        if (c != ',') {
          throw error("expected ',' or ']'");
        }
      }
    }

    String string() {
      expect('"');
      StringBuilder b = new StringBuilder();
      while (true) {
        char c = peek();
        i++;
        if (c == '"') {
          return b.toString();
        }
        if (c == '\\') {
          char e = peek();
          i++;
          switch (e) {
            case '"', '\\', '/' -> b.append(e);
            case 'b' -> b.append('\b');
            case 'f' -> b.append('\f');
            case 'n' -> b.append('\n');
            case 'r' -> b.append('\r');
            case 't' -> b.append('\t');
            case 'u' -> {
              if (i + 4 > s.length()) {
                throw error("bad \\u escape");
              }
              try {
                b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
              } catch (NumberFormatException ex) {
                throw error("bad \\u escape");
              }
              i += 4;
            }
            default -> throw error("bad escape");
          }
        } else if (c < 0x20) {
          throw error("control character in string");
        } else {
          b.append(c);
        }
      }
    }

    Object number() {
      int start = i;
      if (peek() == '-') {
        i++;
      }
      if (peek() == 'I') {
        literal("Infinity");
        return Double.NEGATIVE_INFINITY;
      }
      if (peek() == '0') {
        i++;
        if (i < s.length() && Character.isDigit(s.charAt(i))) {
          throw error("leading zero");
        }
      } else {
        digits();
      }
      boolean integral = true;
      if (i < s.length() && s.charAt(i) == '.') {
        integral = false;
        i++;
        digits();
      }
      if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
        integral = false;
        i++;
        if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) {
          i++;
        }
        digits();
      }
      String text = s.substring(start, i);
      if (integral) {
        try {
          return Long.parseLong(text);
        } catch (NumberFormatException e) {
          // wider than a long: fall through to a double
        }
      }
      try {
        return Double.parseDouble(text);
      } catch (NumberFormatException e) {
        throw error("bad number");
      }
    }

    void digits() {
      int start = i;
      while (i < s.length() && Character.isDigit(s.charAt(i))) {
        i++;
      }
      if (i == start) {
        throw error("expected digits");
      }
    }
  }

  /**
   * Compact serialisation (no spaces), map insertion order kept; non-finite numbers become null.
   */
  public static String stringify(Object v) {
    StringBuilder b = new StringBuilder();
    write(v, b);
    return b.toString();
  }

  private static void write(Object v, StringBuilder b) {
    if (v == null) {
      b.append("null");
    } else if (v instanceof String s) {
      writeString(s, b);
    } else if (v instanceof Boolean) {
      b.append(v);
    } else if (v instanceof Double || v instanceof Float) {
      double d = ((Number) v).doubleValue();
      if (Double.isNaN(d) || Double.isInfinite(d)) {
        b.append("null");
      } else {
        b.append(d);
      }
    } else if (v instanceof Number) {
      b.append(v);
    } else if (v instanceof Map<?, ?> m) {
      b.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> e : m.entrySet()) {
        if (!first) {
          b.append(',');
        }
        first = false;
        writeString(String.valueOf(e.getKey()), b);
        b.append(':');
        write(e.getValue(), b);
      }
      b.append('}');
    } else if (v instanceof Iterable<?> it) {
      b.append('[');
      boolean first = true;
      for (Object o : it) {
        if (!first) {
          b.append(',');
        }
        first = false;
        write(o, b);
      }
      b.append(']');
    } else {
      throw new IllegalArgumentException("camada: not JSON-serialisable: " + v.getClass());
    }
  }

  private static void writeString(String s, StringBuilder b) {
    b.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        case '\b' -> b.append("\\b");
        case '\f' -> b.append("\\f");
        default -> {
          if (c < 0x20) {
            b.append(String.format("\\u%04x", (int) c));
          } else {
            b.append(c);
          }
        }
      }
    }
    b.append('"');
  }
}
