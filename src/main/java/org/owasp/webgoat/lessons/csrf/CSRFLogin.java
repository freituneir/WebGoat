/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(HttpServletRequest request, @CurrentUsername String username) {
    // What this assignment reports is "you are signed in as an account somebody else chose for
    // you" - login CSRF. {@link LoginCsrfFilter} refuses an authentication request that another
    // site submitted, so a session can only be signed in by whoever typed the credentials into
    // WebGoat's own form. Requiring a deliberate login here would be the opposite test: it is
    // satisfied by registering an account whose name happens to start with "csrf" and signing in
    // normally, which proves nothing about forgery. There is no longer any state of this session
    // that indicates a forged login, so the assignment cannot be completed.
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}
