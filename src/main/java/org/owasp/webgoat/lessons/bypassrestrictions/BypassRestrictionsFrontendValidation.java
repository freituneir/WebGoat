/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFrontendValidation implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/frontendValidation")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String field1,
      @RequestParam String field2,
      @RequestParam String field3,
      @RequestParam String field4,
      @RequestParam String field5,
      @RequestParam String field6,
      @RequestParam String field7,
      @RequestParam Integer error) {
    final String regex1 = "^[a-z]{3}$";
    final String regex2 = "^[0-9]{3}$";
    final String regex3 = "^[a-zA-Z0-9 ]*$";
    final String regex4 = "^(one|two|three|four|five|six|seven|eight|nine)$";
    final String regex5 = "^\\d{5}$";
    final String regex6 = "^\\d{5}(-\\d{4})?$";
    final String regex7 = "^[2-9]\\d{2}-?\\d{3}-?\\d{4}$";
    // The JavaScript that enforces these patterns in the browser is a usability aid, not a
    // control: it can be disabled or side-stepped entirely. Every field is therefore re-validated
    // here against the exact same patterns, and a submission that does not satisfy all of them is
    // rejected regardless of what the client reported in "error".
    if (!field1.matches(regex1)
        || !field2.matches(regex2)
        || !field3.matches(regex3)
        || !field4.matches(regex4)
        || !field5.matches(regex5)
        || !field6.matches(regex6)
        || !field7.matches(regex7)) {
      return failed(this)
          .output("One or more fields failed server-side validation; the submission was rejected.")
          .build();
    }
    return failed(this).build();
  }
}
