package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.unimo.sdk.shared.Json;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Options serialise sparsely (the gateway treats null and "" as unset, but we omit them) and image rows parse. */
class SearchTest {
  @Test
  void optionsOmitUnsetFields() {
    Search.Options o = new Search.Options();
    assertNull(o.toJson());
    o.country = "DE";
    o.city = "";
    o.safesearch = "off";
    assertEquals(Json.obj("country", "DE", "safesearch", "off"), o.toJson());
  }

  @Test
  void imageRowsParseWithOptionalSize() {
    Map<String, Object> frame = Json.parseObject(
        "{\"type\":\"search:results\",\"cached\":false,\"data\":{\"query\":\"q\",\"results\":["
            + "{\"title\":\"t\",\"url\":\"https://a/\",\"src\":\"https://cdn/x.jpg\",\"width\":640,\"height\":480},"
            + "{\"title\":\"u\",\"url\":\"https://b/\",\"src\":\"https://cdn/y.jpg\"}]}}");
    Search.ImageResponse r = Search.parseImageResponse(frame);
    assertEquals(2, r.results.size());
    assertEquals(640, r.results.get(0).width);
    assertNull(r.results.get(1).width);
    assertEquals("https://cdn/y.jpg", r.results.get(1).src);
  }
}
