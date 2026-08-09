/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static java.util.Optional.ofNullable;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class SimpleMailAssignment implements AssignmentEndpoint {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final String webWolfURL;
  private final String webGoatURL;
  private RestTemplate restTemplate;

  /** Single-use reset tokens that were mailed out, mapped to the account they belong to. */
  private final Map<String, String> resetTokens = new ConcurrentHashMap<>();

  /** The password each account chose for itself; nothing here was ever sent anywhere. */
  private final Map<String, String> chosenPasswords = new ConcurrentHashMap<>();

  public SimpleMailAssignment(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.webGoatURL = webGoatURL;
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
    String chosenPassword = chosenPasswords.get(username);

    if (username.equals(webGoatUsername)
        && chosenPassword != null
        && MessageDigest.isEqual(
            chosenPassword.getBytes(StandardCharsets.UTF_8),
            ofNullable(password).orElse("").getBytes(StandardCharsets.UTF_8))) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("password-reset-simple.password_incorrect").build();
    }
  }

  /**
   * Redeems a mailed reset token and records the password the account holder picked. The token is
   * consumed here: it authorises exactly one password change and is worth nothing afterwards.
   */
  @PostMapping(
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      produces = MediaType.TEXT_HTML_VALUE,
      value = "/PasswordReset/simple-mail/choose-password")
  @ResponseBody
  public String choosePassword(
      @RequestParam String token, @RequestParam String password, @CurrentUsername String username) {
    String owner = token == null ? null : resetTokens.remove(token);
    if (owner == null || !owner.equals(username) || !StringUtils.hasText(password)) {
      return "<html><body>That reset link is not valid any more.</body></html>";
    }
    chosenPasswords.put(owner, password);
    return "<html><body>Your password has been changed, you can log in with it now.</body></html>";
  }

  /** The page the mailed link opens, so the account holder can pick a password. */
  @GetMapping(
      value = "/PasswordReset/simple-mail/choose-password",
      produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String choosePasswordForm(@RequestParam String token) {
    return """
        <html><body>
        <form method="POST" action="/WebGoat/PasswordReset/simple-mail/choose-password">
          <input type="hidden" name="token" value="%s"/>
          <label>Choose a new password: <input type="password" name="password"/></label>
          <input type="submit" value="Change password"/>
        </form>
        </body></html>
        """
        .formatted(HtmlUtils.htmlEscape(token));
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

  /** A reset token must be unpredictable, so it is drawn from a secure random generator. */
  private String createResetToken() {
    byte[] randomBytes = new byte[16];
    SECURE_RANDOM.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }

  private AttackResult sendEmail(String username, String email, String webGoatUsername) {
    if (username.equals(webGoatUsername)) {
      // A password is never mailed. Mail carries a single-use token that authorises the account
      // holder to choose their own password: a credential that arrives by e-mail is readable by
      // anyone who can reach the mailbox, and it stays valid until somebody notices.
      String resetToken = createResetToken();
      PasswordResetEmail mailEvent =
          PasswordResetEmail.builder()
              .recipient(username)
              .title("Simple e-mail assignment")
              .time(LocalDateTime.now())
              .contents(
                  "To choose a new password, open "
                      + webGoatURL
                      + "/PasswordReset/simple-mail/choose-password?token="
                      + resetToken)
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
      resetTokens.put(resetToken, username);
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
