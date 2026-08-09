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
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  /**
   * The server no longer performs an outbound request for a client supplied URL. The parameter is
   * only a key into a strict server-side allow-list of the resources this page offers; anything
   * else is rejected without any network access.
   */
  private static final Map<String, String> ALLOWED_IMAGES =
      Map.of(
          "images/cat.png", "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">",
          "images/cat.jpg", "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    String image = ALLOWED_IMAGES.get(url);
    if (image == null) {
      return getFailedResult(
          "This server only serves the images offered by this page, it does not fetch"
              + " client-supplied URLs.");
    }
    return getFailedResult(image);
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
