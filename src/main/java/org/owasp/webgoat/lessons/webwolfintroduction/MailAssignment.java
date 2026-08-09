/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class MailAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final int CODE_BYTES = 16;

  private final String webWolfURL;
  private RestTemplate restTemplate;

  /**
   * The code that was mailed out, per user. It is drawn at random rather than derived from the
   * account name: a code anyone can compute for anyone proves nothing about who received the mail.
   */
  private final Map<String, String> mailedCodes = new ConcurrentHashMap<>();

  public MailAssignment(
      RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
  }

  @PostMapping("/WebWolf/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam String email, @CurrentUsername String webGoatUsername) {
    String username = email.substring(0, email.indexOf("@"));
    if (username.equalsIgnoreCase(webGoatUsername)) {
      Email mailEvent =
          Email.builder()
              .recipient(username)
              .title("Test messages from WebWolf")
              .contents(
                  "This is a test message from WebWolf, your unique code is: "
                      + issueCode(webGoatUsername))
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("webwolf.email_failed")
            .output(e.getMessage())
            .build();
      }
      return informationMessage(this).feedback("webwolf.email_send").feedbackArgs(email).build();
    } else {
      return informationMessage(this)
          .feedback("webwolf.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }

  @PostMapping("/WebWolf/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    // One shot: the mailed code is consumed by the first attempt, so it cannot be replayed and
    // cannot be brute-forced over repeated submissions.
    String mailedCode = mailedCodes.remove(username);
    if (mailedCode != null && uniqueCode != null && constantTimeEquals(mailedCode, uniqueCode)) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("webwolf.code_incorrect").feedbackArgs(uniqueCode).build();
    }
  }

  private String issueCode(String username) {
    byte[] code = new byte[CODE_BYTES];
    SECURE_RANDOM.nextBytes(code);
    String uniqueCode = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    mailedCodes.put(username, uniqueCode);
    return uniqueCode;
  }

  private static boolean constantTimeEquals(String issued, String submitted) {
    return MessageDigest.isEqual(
        issued.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }
}
