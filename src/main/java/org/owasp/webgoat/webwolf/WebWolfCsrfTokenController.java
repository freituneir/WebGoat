/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebWolf runs in its own application context, so it needs its own copy of the token endpoint that
 * WebGoat exposes. See {@code org.owasp.webgoat.container.WebGoatCsrfTokenController}.
 */
@RestController
public class WebWolfCsrfTokenController {

  @GetMapping("/csrf/token")
  public Token token(CsrfToken csrfToken) {
    return new Token(
        csrfToken.getToken(), csrfToken.getHeaderName(), csrfToken.getParameterName());
  }

  record Token(String token, String headerName, String parameterName) {}
}
