/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
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
    if (username.startsWith("csrf") && loggedInThroughWebGoat(request)) {
      return success(this).feedback("csrf-login-success").build();
    }
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }

  /**
   * Counts only if the credentials for this session came from WebGoat's own login form. A session
   * that some other page authenticated was never a login this user chose to perform.
   */
  private boolean loggedInThroughWebGoat(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    return session != null
        && Boolean.TRUE.equals(session.getAttribute(LoginCsrfFilter.LOGIN_FROM_WEBGOAT));
  }
}
