/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_SELECT_VALUES = Set.of("option1", "option2");
  private static final Set<String> ALLOWED_RADIO_VALUES = Set.of("option1", "option2");
  private static final Set<String> ALLOWED_CHECKBOX_VALUES = Set.of("on", "off");
  private static final int SHORT_INPUT_MAX_LENGTH = 5;
  private static final String READ_ONLY_VALUE = "change";

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // The select/radio/checkbox/maxlength/readonly attributes only constrain the browser. The
    // very same constraints are re-applied here, on the server, where the client cannot reach
    // them: every field is checked against the allow-list of values the form is able to produce.
    if (!ALLOWED_SELECT_VALUES.contains(select)
        || !ALLOWED_RADIO_VALUES.contains(radio)
        || !ALLOWED_CHECKBOX_VALUES.contains(checkbox)
        || shortInput.length() > SHORT_INPUT_MAX_LENGTH
        || !READ_ONLY_VALUE.equals(readOnlyInput)) {
      return failed(this).output(REJECTED).build();
    }
    return failed(this).build();
  }

  private static final String REJECTED =
      "One or more fields did not pass server-side validation and the submission was rejected.";
}
