/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint1", "ssrf.hint2"})
public class SSRFTask1 implements AssignmentEndpoint {

  /**
   * Strict server-side allow-list: the request parameter is only a key, never a resource path. The
   * server decides which resources it is willing to serve, so a client cannot ask for a resource
   * this page never offered.
   */
  private static final Map<String, String> ALLOWED_IMAGES =
      Map.of(
          "images/tom.png",
          "<img class=\"image\" alt=\"Tom\" src=\"images/tom.png\" width=\"25%\" height=\"25%\">");

  @PostMapping("/SSRF/task1")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return stealTheCheese(url);
  }

  protected AttackResult stealTheCheese(String url) {
    String image = ALLOWED_IMAGES.get(url);
    if (image == null) {
      return failed(this)
          .feedback("ssrf.failure")
          .output("<img class=\"image\" alt=\"Silly Cat\" src=\"images/cat.jpg\">")
          .build();
    }
    return failed(this).feedback("ssrf.tom").output(image).build();
  }
}
