/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-feedback-hint1", "csrf-feedback-hint2", "csrf-feedback-hint3"})
public class CSRFFeedback implements AssignmentEndpoint {

  private final LessonSession userSessionData;
  private final ObjectMapper objectMapper;

  public CSRFFeedback(LessonSession userSessionData, ObjectMapper objectMapper) {
    this.userSessionData = userSessionData;
    this.objectMapper = objectMapper;
  }

  @PostMapping(
      value = "/csrf/feedback/message",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(HttpServletRequest request, @RequestBody String feedback) {
    // A form on another site can only post one of the three simple content types. Feedback is
    // JSON, so anything else is turned away before the body is even parsed.
    String contentType = request.getContentType();
    if (contentType == null
        || !contentType.toLowerCase(Locale.ROOT).contains(MediaType.APPLICATION_JSON_VALUE)) {
      return failed(this).feedback("csrf-feedback-invalid-content-type").build();
    }
    // And the request has to prove it started in WebGoat itself.
    if (!OriginCheck.fromThisApplication(request)) {
      return failed(this).feedback("csrf-request-rejected").build();
    }
    try {
      objectMapper.enable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS);
      objectMapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
      objectMapper.enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
      objectMapper.readValue(feedback.getBytes(), Map.class);
    } catch (IOException e) {
      return failed(this).feedback(ExceptionUtils.getStackTrace(e)).build();
    }
    return failed(this).build();
  }

  @PostMapping(path = "/csrf/feedback", produces = "application/json")
  @ResponseBody
  public AttackResult flag(@RequestParam("confirmFlagVal") String flag) {
    Object expectedFlag = userSessionData.getValue("csrf-feedback");
    if (expectedFlag != null && flag.equals(expectedFlag)) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }
}
