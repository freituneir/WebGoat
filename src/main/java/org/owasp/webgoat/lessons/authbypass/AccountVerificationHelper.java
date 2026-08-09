/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    boolean likely = false;

    if (submittedAnswers.size() == secQuestionStore.get(verifyUserId).size()) {
      likely = true;
    }

    if ((submittedAnswers.containsKey("secQuestion0")
            && submittedAnswers
                .get("secQuestion0")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion0")))
        && (submittedAnswers.containsKey("secQuestion1")
            && submittedAnswers
                .get("secQuestion1")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion1")))) {
      likely = true;
    } else {
      likely = false;
    }

    return likely;
  }

  // end of cheating check ... the method below is the one of real interest. Can you find the flaw?

  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    Map<String, String> expectedAnswers = secQuestionStore.get(userId);
    if (expectedAnswers == null) {
      return false;
    }

    // Drive the check from the questions on record, never from the keys the client chose to send:
    // every question on record must be answered and every answer must match. Unexpected keys are
    // rejected as well, so a request cannot satisfy the count while skipping every real question.
    if (submittedQuestions.size() != expectedAnswers.size()
        || !submittedQuestions.keySet().containsAll(expectedAnswers.keySet())) {
      return false;
    }

    for (Map.Entry<String, String> question : expectedAnswers.entrySet()) {
      String submittedAnswer = submittedQuestions.get(question.getKey());
      if (submittedAnswer == null || !constantTimeEquals(submittedAnswer, question.getValue())) {
        return false;
      }
    }

    return true;
  }

  private static boolean constantTimeEquals(String submitted, String expected) {
    return MessageDigest.isEqual(
        submitted.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
  }
}
