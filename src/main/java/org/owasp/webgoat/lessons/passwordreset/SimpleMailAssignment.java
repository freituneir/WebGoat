/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static java.util.Optional.ofNullable;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
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
public class SimpleMailAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final String webWolfURL;
  private final RestTemplate restTemplate;
  private final Map<String, String> passwords = new ConcurrentHashMap<>();

  public SimpleMailAssignment(
      RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
  }

  @PostMapping(
      path = "/PasswordReset/simple-mail",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult login(
      @RequestParam String email,
      @RequestParam String password,
      @CurrentUsername String webGoatUsername) {
    String emailAddress = ofNullable(email).orElse("unknown@webgoat.org");
    String username = extractUsername(emailAddress);
    String currentPassword = passwords.get(webGoatUsername);

    // Nothing is derived from the user name any more; the input is compared with the random
    // value that was generated for the account of whoever is signed in.
    if (username.equals(webGoatUsername)
        && currentPassword != null
        && currentPassword.equals(password)) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("password-reset-simple.password_incorrect").build();
    }
  }

  @PostMapping(
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      value = "/PasswordReset/simple-mail/reset")
  @ResponseBody
  public AttackResult resetPassword(
      @RequestParam String emailReset, @CurrentUsername String username) {
    String email = ofNullable(emailReset).orElse("unknown@webgoat.org");
    return sendEmail(extractUsername(email), email, username);
  }

  private String extractUsername(String email) {
    int index = email.indexOf("@");
    return email.substring(0, index == -1 ? email.length() : index);
  }

  private String randomPassword() {
    byte[] password = new byte[24];
    SECURE_RANDOM.nextBytes(password);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(password);
  }

  private AttackResult sendEmail(String username, String email, String webGoatUsername) {
    if (username.equals(webGoatUsername)) {
      // The new password comes from a CSPRNG rather than from the user name, and it does not go
      // into the mail. The message only says that a reset happened.
      passwords.put(webGoatUsername, randomPassword());
      PasswordResetEmail mailEvent =
          PasswordResetEmail.builder()
              .recipient(username)
              .title("Simple e-mail assignment")
              .time(LocalDateTime.now())
              .contents(
                  "We received a request to reset the password of your account. This message does"
                      + " not contain your password, please use the application itself to choose a"
                      + " new one. If you did not request this you can ignore this message.")
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("password-reset-simple.email_failed")
            .output(e.getMessage())
            .build();
      }
      return informationMessage(this)
          .feedback("password-reset-simple.email_send")
          .feedbackArgs(email)
          .build();
    } else {
      return informationMessage(this)
          .feedback("password-reset-simple.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }
}
