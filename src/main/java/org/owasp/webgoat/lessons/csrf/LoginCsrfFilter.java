/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Refuses a sign in that was submitted by another site.
 *
 * <p>Login CSRF is the mirror image of the usual attack: instead of acting as the victim, the
 * attacker quietly signs the victim in on an account the attacker owns. Everything the victim does
 * afterwards - the lessons solved, the data entered - lands in that account. Registration is covered
 * too because creating an account authenticates it right away.
 *
 * <p>A request that does not say where it came from is let through: command line clients and the
 * integration tests never send those headers, and a request without cookies attached by a browser is
 * not the attack this guards against. Whether the login was proven to come from WebGoat is recorded
 * on the session, {@link CSRFLogin} uses that to judge its assignment.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoginCsrfFilter extends OncePerRequestFilter {

  /** Session flag: were the credentials for this session typed into WebGoat's own login form? */
  static final String LOGIN_FROM_WEBGOAT = "csrf-login-from-webgoat";

  private static final String LOGIN = "/login";
  private static final Set<String> GUARDED_PATHS = Set.of(LOGIN, "/register.mvc");

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (OriginCheck.fromAnotherSite(request)) {
      response.sendRedirect(request.getContextPath() + LOGIN + "?error");
      return;
    }
    if (LOGIN.equals(applicationPath(request))) {
      // recorded on every attempt: an earlier verified login may not vouch for a later one
      request
          .getSession()
          .setAttribute(LOGIN_FROM_WEBGOAT, OriginCheck.fromThisApplication(request));
    }
    chain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !"POST".equalsIgnoreCase(request.getMethod())
        || !GUARDED_PATHS.contains(applicationPath(request));
  }

  private String applicationPath(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (path == null) {
      return "";
    }
    String context = request.getContextPath();
    if (context != null && !context.isEmpty() && path.startsWith(context)) {
      path = path.substring(context.length());
    }
    // strip a ;jsessionid style path parameter so it cannot be used to slip past the comparison
    int parameter = path.indexOf(';');
    return parameter < 0 ? path : path.substring(0, parameter);
  }
}
