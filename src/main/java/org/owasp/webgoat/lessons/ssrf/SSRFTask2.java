/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.List;
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

  /** The only resources this page is allowed to render, everything else is rejected. */
  private static final List<String> ALLOWED_IMAGES = List.of("images/cat.png", "images/cat.jpg");

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    // No outbound connection is ever opened for a value that came in with the request; the page
    // only renders its own images, checked against a list held on this side.
    if (!ALLOWED_IMAGES.contains(url)) {
      return getFailedResult("Only the images on this page can be requested");
    }
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
