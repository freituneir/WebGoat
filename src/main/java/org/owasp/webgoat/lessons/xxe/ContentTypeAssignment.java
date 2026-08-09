/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Optional;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.CurrentUser;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"xxe.hints.content.type.xxe.1", "xxe.hints.content.type.xxe.2"})
public class ContentTypeAssignment implements AssignmentEndpoint {

  private final CommentsCache comments;

  public ContentTypeAssignment(CommentsCache comments) {
    this.comments = comments;
  }

  @PostMapping(path = "xxe/content-type")
  @ResponseBody
  public AttackResult createNewUser(
      @RequestBody String commentStr,
      @RequestHeader("Content-Type") String contentType,
      @CurrentUser WebGoatUser user) {
    AttackResult attackResult = failed(this).build();

    if (APPLICATION_JSON_VALUE.equals(contentType)) {
      parseJson(commentStr).ifPresent(c -> comments.addComment(c, user, true));
      attackResult = failed(this).feedback("xxe.content.type.feedback.json").build();
    }

    if (null != contentType && contentType.contains(MediaType.APPLICATION_XML_VALUE)) {
      try {
        Comment comment = comments.parseXml(commentStr, true);
        comments.addComment(comment, user, false);
      } catch (Exception e) {
        String error = ExceptionUtils.getStackTrace(e);
        attackResult = failed(this).feedback("xxe.content.type.feedback.xml").output(error).build();
      }
    }

    return attackResult;
  }

  protected Optional<Comment> parseJson(String comment) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      return of(mapper.readValue(comment, Comment.class));
    } catch (IOException e) {
      return empty();
    }
  }

}
