/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class LandingAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final int CODE_BYTES = 16;

  private final String landingPageUrl;

  /**
   * The codes handed out so far, per user. A callback code proves that the holder went through the
   * channel it was delivered on, which it can only do if it was not derivable in the first place —
   * so it is drawn at random here and kept server-side, never computed from the user's name.
   */
  private final Map<String, String> issuedCodes = new ConcurrentHashMap<>();

  public LandingAssignment(@Value("${webwolf.landingpage.url}") String landingPageUrl) {
    this.landingPageUrl = landingPageUrl;
  }

  @PostMapping("/WebWolf/landing")
  @ResponseBody
  public AttackResult click(String uniqueCode, @CurrentUsername String username) {
    String issuedCode = issuedCodes.get(username);
    if (issuedCode != null && uniqueCode != null && constantTimeEquals(issuedCode, uniqueCode)) {
      return success(this).build();
    }
    return failed(this).feedback("webwolf.landing_wrong").build();
  }

  @GetMapping("/WebWolf/landing/password-reset")
  public ModelAndView openPasswordReset(@CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    modelAndView.addObject(
        "webwolfLandingPageUrl", landingPageUrl.replace("//landing", "/landing"));
    modelAndView.addObject("uniqueCode", issueCode(username));

    modelAndView.setViewName("lessons/webwolfintroduction/templates/webwolfPasswordReset.html");
    return modelAndView;
  }

  private String issueCode(String username) {
    byte[] code = new byte[CODE_BYTES];
    SECURE_RANDOM.nextBytes(code);
    String uniqueCode = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    issuedCodes.put(username, uniqueCode);
    return uniqueCode;
  }

  private static boolean constantTimeEquals(String issued, String submitted) {
    return MessageDigest.isEqual(
        issued.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }
}
