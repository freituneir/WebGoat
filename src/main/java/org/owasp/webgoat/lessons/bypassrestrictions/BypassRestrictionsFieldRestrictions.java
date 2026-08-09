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
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final int MAX_SHORT_INPUT = 5;

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // Whatever the form widgets allow is checked again on this side. A value the rendered form
    // could not have produced is refused instead of being taken at face value.
    if (!matchesFormRestrictions(select, radio, checkbox, shortInput, readOnlyInput)) {
      return failed(this).feedback("bypass-restrictions.intercept.failure").build();
    }
    return failed(this).build();
  }

  private boolean matchesFormRestrictions(
      String select, String radio, String checkbox, String shortInput, String readOnlyInput) {
    return ("option1".equals(select) || "option2".equals(select))
        && ("option1".equals(radio) || "option2".equals(radio))
        && ("on".equals(checkbox) || "off".equals(checkbox))
        && shortInput != null
        && shortInput.length() <= MAX_SHORT_INPUT
        && "change".equals(readOnlyInput);
  }
}
