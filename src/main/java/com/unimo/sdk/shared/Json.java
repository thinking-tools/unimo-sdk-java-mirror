package com.unimo.sdk.shared;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dependency-free JSON: a minimal recursive-descent parser plus a <em>canonical</em>
 * serializer that reproduces {@code JSON.stringify(_canonicalize(x))} from
 * {@code shared/Helpers.ts} byte-for-byte (recursive key sort, compact, ECMAScript string
 * escaping). The canonical form is what gets SHA-256'd and ML-DSA-signed, so it must match
 * the TS SDK exactly.
 *
 * <p>Value model: object = {@link LinkedHashMap}, array = {@link List}, plus String, Long
 * (integral), Double (fractional), Boolean, null. The canonical serializer rejects
 * Double/Float — signed payloads only ever carry integers, and ECMAScript number formatting
 * for non-integers is intentionally not replicated (fail loud rather than diverge silently).
 */
public final class Json {
  private Json() {}

  // ───────────────────────── Builders ─────────────────────────

  /** Ordered JSON object from alternating key/value args. Keys are sorted at canonical time. */
  public static Map<String, Object> obj(Object... kv) {
    if (kv.length % 2 != 0) throw new IllegalArgumentException("obj() needs an even number of args");
    Map<String, Object> m = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
    return m;
  }

  public static List<Object> arr(Object... items) {
    List<Object> a = new ArrayList<>(items.length);
    for (Object o : items) a.add(o);
    return a;
  }

  // ───────────────────────── Canonical serialization ─────────────────────────

  /** Mirror of {@code generateCanonicalJSON}: recursive key sort + compact JSON.stringify. */
  public static String canonical(Object value) {
    StringBuilder sb = new StringBuilder(256);
    writeCanonical(sb, value);
    return sb.toString();
  }

  @SuppressWarnings("unchecked")
  private static void writeCanonical(StringBuilder sb, Object v) {
    if (v == null) {
      sb.append("null");
    } else if (v instanceof Map) {
      Map<String, Object> m = (Map<String, Object>) v;
      List<String> keys = new ArrayList<>(m.keySet());
      Collections.sort(keys); // String natural order == JS default sort for ASCII keys
      sb.append('{');
      for (int i = 0; i < keys.size(); i++) {
        if (i > 0) sb.append(',');
        writeString(sb, keys.get(i));
        sb.append(':');
        writeCanonical(sb, m.get(keys.get(i)));
      }
      sb.append('}');
    } else if (v instanceof List) {
      List<Object> a = (List<Object>) v;
      sb.append('[');
      for (int i = 0; i < a.size(); i++) {
        if (i > 0) sb.append(',');
        writeCanonical(sb, a.get(i));
      }
      sb.append(']');
    } else if (v instanceof String) {
      writeString(sb, (String) v);
    } else if (v instanceof Boolean) {
      sb.append(((Boolean) v) ? "true" : "false");
    } else if (v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte
        || v instanceof java.math.BigInteger) {
      sb.append(v.toString());
    } else if (v instanceof Double || v instanceof Float) {
      throw new IllegalArgumentException(
          "canonical JSON: non-integer number not supported in signed payloads: " + v);
    } else {
      throw new IllegalArgumentException("canonical JSON: unsupported type " + v.getClass());
    }
  }

  /** ECMAScript {@code QuoteJSONString} escaping (forward slash NOT escaped). */
  private static void writeString(StringBuilder sb, String s) {
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b"); break;
        case '\f': sb.append("\\f"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append("\\u");
            for (int shift = 12; shift >= 0; shift -= 4) sb.append("0123456789abcdef".charAt((c >> shift) & 0xf));
          } else {
            sb.append(c);
          }
      }
    }
    sb.append('"');
  }

  // ───────────────────────── Parsing ─────────────────────────

  public static Object parse(String text) {
    Parser p = new Parser(text);
    p.skipWs();
    Object v = p.value();
    p.skipWs();
    if (p.pos != text.length()) throw new IllegalArgumentException("trailing content at " + p.pos);
    return v;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> parseObject(String text) {
    Object v = parse(text);
    if (!(v instanceof Map)) throw new IllegalArgumentException("expected JSON object");
    return (Map<String, Object>) v;
  }

  private static final class Parser {
    final String s;
    int pos;

    Parser(String s) { this.s = s; }

    void skipWs() {
      while (pos < s.length()) {
        char c = s.charAt(pos);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
        else break;
      }
    }

    Object value() {
      char c = peek();
      switch (c) {
        case '{': return object();
        case '[': return array();
        case '"': return string();
        case 't': expect("true"); return Boolean.TRUE;
        case 'f': expect("false"); return Boolean.FALSE;
        case 'n': expect("null"); return null;
        default: return number();
      }
    }

    Map<String, Object> object() {
      Map<String, Object> m = new LinkedHashMap<>();
      pos++; // {
      skipWs();
      if (peek() == '}') { pos++; return m; }
      while (true) {
        skipWs();
        String k = string();
        skipWs();
        if (s.charAt(pos++) != ':') throw err("expected ':'");
        skipWs();
        m.put(k, value());
        skipWs();
        char c = s.charAt(pos++);
        if (c == ',') continue;
        if (c == '}') break;
        throw err("expected ',' or '}'");
      }
      return m;
    }

    List<Object> array() {
      List<Object> a = new ArrayList<>();
      pos++; // [
      skipWs();
      if (peek() == ']') { pos++; return a; }
      while (true) {
        skipWs();
        a.add(value());
        skipWs();
        char c = s.charAt(pos++);
        if (c == ',') continue;
        if (c == ']') break;
        throw err("expected ',' or ']'");
      }
      return a;
    }

    String string() {
      if (s.charAt(pos++) != '"') throw err("expected string");
      StringBuilder sb = new StringBuilder();
      while (true) {
        char c = s.charAt(pos++);
        if (c == '"') break;
        if (c == '\\') {
          char e = s.charAt(pos++);
          switch (e) {
            case '"': sb.append('"'); break;
            case '\\': sb.append('\\'); break;
            case '/': sb.append('/'); break;
            case 'b': sb.append('\b'); break;
            case 'f': sb.append('\f'); break;
            case 'n': sb.append('\n'); break;
            case 'r': sb.append('\r'); break;
            case 't': sb.append('\t'); break;
            case 'u':
              sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
              pos += 4;
              break;
            default: throw err("bad escape \\" + e);
          }
        } else {
          sb.append(c);
        }
      }
      return sb.toString();
    }

    Object number() {
      int start = pos;
      boolean fractional = false;
      while (pos < s.length()) {
        char c = s.charAt(pos);
        if (c >= '0' && c <= '9' || c == '-' || c == '+') {
          pos++;
        } else if (c == '.' || c == 'e' || c == 'E') {
          fractional = true;
          pos++;
        } else {
          break;
        }
      }
      String num = s.substring(start, pos);
      if (num.isEmpty()) throw err("invalid number");
      return fractional ? (Object) Double.valueOf(num) : (Object) Long.valueOf(num);
    }

    char peek() {
      if (pos >= s.length()) throw err("unexpected end");
      return s.charAt(pos);
    }

    void expect(String lit) {
      if (!s.regionMatches(pos, lit, 0, lit.length())) throw err("expected '" + lit + "'");
      pos += lit.length();
    }

    IllegalArgumentException err(String msg) {
      return new IllegalArgumentException("JSON parse: " + msg + " at " + pos);
    }
  }
}
