/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.idorDiffAttributes1",
  "idor.hints.idorDiffAttributes2",
  "idor.hints.idorDiffAttributes3"
})
public class IDORDiffAttributes implements AssignmentEndpoint {

  /** Profile attributes the lesson page renders, see lessons/idor/js/idor.js. */
  private static final Set<String> RENDERED_ATTRIBUTES = Set.of("name", "color", "size");

  /**
   * The attributes the profile endpoint returns on top of what the page renders. This is derived
   * from the response instead of being hard coded, and since the profile endpoint now only
   * serializes the attributes the owner is entitled to see, nothing is withheld from the page.
   */
  private static final Set<String> UNDISPLAYED_ATTRIBUTES = undisplayedAttributes();

  private static Set<String> undisplayedAttributes() {
    Set<String> undisplayed = new HashSet<>(UserProfile.DISCLOSED_ATTRIBUTES);
    undisplayed.removeAll(RENDERED_ATTRIBUTES);
    return undisplayed;
  }

  @PostMapping("/IDOR/diff-attributes")
  @ResponseBody
  public AttackResult completed(@RequestParam String attributes) {
    Set<String> submittedAttributes =
        Arrays.stream(attributes.trim().split(","))
            .map(attribute -> attribute.trim().toLowerCase(Locale.ROOT))
            .filter(attribute -> !attribute.isEmpty())
            .collect(Collectors.toSet());
    if (submittedAttributes.size() < 2) {
      return failed(this).feedback("idor.diff.attributes.missing").build();
    }
    if (UNDISPLAYED_ATTRIBUTES.equals(submittedAttributes)) {
      return success(this).feedback("idor.diff.success").build();
    } else {
      return failed(this).feedback("idor.diff.failure").build();
    }
  }
}
