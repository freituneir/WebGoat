/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Spring Security hands out the CSRF token lazily, the cookie is only written once something asks
 * for its value. The single page front end reads that cookie before it posts anything, so the token
 * is resolved here on every request instead of waiting for a form to render.
 */
public final class CsrfTokenCookieFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    var token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    if (token != null) {
      // resolving the value is what makes the repository write the cookie
      token.getToken();
    }
    chain.doFilter(request, response);
  }
}
