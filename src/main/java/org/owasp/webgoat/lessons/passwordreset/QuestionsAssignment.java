/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final int MAX_ATTEMPTS = 3;
  private static final Duration LOCK_OUT_PERIOD = Duration.ofMinutes(5);

  /** The answer of a security question is a secret, only a salted hash of it is stored. */
  private static final Map<String, String> ANSWERS = new HashMap<>();

  static {
    ANSWERS.put("admin", hash("admin", "green"));
    ANSWERS.put("jerry", hash("jerry", "orange"));
    ANSWERS.put("tom", hash("tom", "purple"));
    ANSWERS.put("larry", hash("larry", "yellow"));
    ANSWERS.put("webgoat", hash("webgoat", "red"));
  }

  private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
  private final Map<String, Instant> lockedOutUntil = new ConcurrentHashMap<>();

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(
      @RequestParam Map<String, Object> json, @CurrentUsername String currentUsername) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");
    String account = username.toLowerCase();

    Instant lockedUntil = lockedOutUntil.get(account);
    if (lockedUntil != null) {
      if (Instant.now().isBefore(lockedUntil)) {
        return failed(this).feedback("password-questions-locked-out").build();
      }
      lockedOutUntil.remove(account);
      failedAttempts.remove(account);
    }

    // A favourite colour is one of a handful of plausible values, so the answer to a security
    // question is never enough to recover an account by itself. Answering correctly for somebody
    // else's account is precisely the takeover this lesson is about, and answering for the account
    // you are already signed in as proves nothing. In both cases the answer only gets the reset
    // link sent to the address the account is registered under, where its owner can act on it.
    String expectedAnswer = ANSWERS.get(account);
    boolean answerCorrect =
        expectedAnswer != null
            && MessageDigest.isEqual(
                expectedAnswer.getBytes(StandardCharsets.UTF_8),
                hash(account, securityQuestion).getBytes(StandardCharsets.UTF_8));
    if (answerCorrect) {
      failedAttempts.remove(account);
      return failed(this).feedback("password-questions-reset-link-sent").build();
    }

    if (failedAttempts.merge(account, 1, Integer::sum) >= MAX_ATTEMPTS) {
      lockedOutUntil.put(account, Instant.now().plus(LOCK_OUT_PERIOD));
    }
    // One and the same message for every failure, it should not leak whether the account exists
    // or which part of the request was wrong.
    return failed(this).feedback("password-questions-failed").build();
  }

  private static String hash(String account, String answer) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      // the account name is used as the salt, equal answers do not result in equal hashes
      digest.update(account.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of()
          .formatHex(digest.digest(answer.toLowerCase().getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
