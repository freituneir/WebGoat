/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lets a client which cannot read the token cookie (tests, scripts) obtain a token before it posts.
 * Reading the token is a safe operation, minting it does not authorise anything by itself.
 */
@RestController
public class WebGoatCsrfTokenController {

  @GetMapping("/csrf/token")
  public Token token(CsrfToken csrfToken) {
    return new Token(
        csrfToken.getToken(), csrfToken.getHeaderName(), csrfToken.getParameterName());
  }

  record Token(String token, String headerName, String parameterName) {}
}
