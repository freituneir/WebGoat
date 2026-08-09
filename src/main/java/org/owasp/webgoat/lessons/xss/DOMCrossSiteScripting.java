/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DOMCrossSiteScripting implements AssignmentEndpoint {

  @PostMapping("/CrossSiteScripting/phone-home-xss")
  @ResponseBody
  public AttackResult completed(@RequestParam Integer param1, @RequestParam Integer param2) {
    // The parameters and the 'webgoat-requested-by' header are fully controlled by whoever calls
    // this endpoint, so they are no proof that the call was made by code running inside the page.
    // They therefore no longer authorize anything: the callback does not complete the assignment
    // and it does not hand out the session secret which the follow-up assignments verify.
    return failed(this).output("phoneHome callback received, no session data returned.").build();
  }
}
