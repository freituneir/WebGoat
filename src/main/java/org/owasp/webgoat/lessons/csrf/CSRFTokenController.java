/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Hands the anti-CSRF token of the current session to the lesson page. Only same origin script can
 * read this response, a cross site page cannot.
 */
@RestController
public class CSRFTokenController {

  @GetMapping(path = "/csrf/token", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Map<String, String> token(HttpSession session) {
    return Map.of("token", CsrfProtection.tokenFor(session));
  }
}
