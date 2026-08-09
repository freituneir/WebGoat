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
    // Without the anti-CSRF token of this session, and an Origin/Referer belonging to this
    // application, the request is not proven to have been sent by the user, so it is not acted on.
    if (!CsrfProtection.hasValidToken(request) || !CsrfProtection.isSameOrigin(request)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }
    // What this assignment reports is "your browser was signed in as somebody else's account by a
    // request another site made on your behalf". Authentication is now bound to an unguessable
    // per-session token and to this application's own origin, so a session can only be established
    // by a request the user themselves issued — whichever account is signed in here, it was not put
    // there by a forged one, and there is no such finding left to report.
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}
