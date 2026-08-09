/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.regex.Pattern;
import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  /** CR, LF and every other control character: the separators an attacker forges entries with. */
  private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output("Please provide a username").build();
    }

    // Untrusted data is neutralised before it becomes part of a log entry: control characters are
    // replaced so a value can never terminate the current line and fabricate a second one, and the
    // result is HTML-encoded because this log viewer renders its entries as markup.
    String loggedUsername =
        HtmlUtils.htmlEscape(CONTROL_CHARACTERS.matcher(username).replaceAll(""));

    return failed(this).output("Login failed for username: " + loggedUsername).build();
  }
}
