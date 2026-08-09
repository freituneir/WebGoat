/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@AssignmentHints({
  "xxe.blind.hints.1",
  "xxe.blind.hints.2",
  "xxe.blind.hints.3",
  "xxe.blind.hints.4",
  "xxe.blind.hints.5"
})
public class BlindSendFileAssignment implements AssignmentEndpoint, Initializable {

  private final String webGoatHomeDirectory;
  private final CommentsCache comments;
  private final Map<WebGoatUser, String> userToFileContents = new HashMap<>();

  public BlindSendFileAssignment(
      @Value("${webgoat.user.directory}") String webGoatHomeDirectory, CommentsCache comments) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
    this.comments = comments;
  }

  private void createSecretFileWithRandomContents(WebGoatUser user) {
    // The value the assignment asks you to exfiltrate. RandomStringUtils is java.util.Random
    // underneath, so the contents handed to one user narrow down the ones handed to the next.
    var fileContents = "WebGoat 8.0 rocks... (" + randomMarker() + ")";
    userToFileContents.put(user, fileContents);
    // The secret is no longer written to the filesystem. A value that is enough on its own to
    // complete this assignment is a credential, and a credential dropped in a file on the server
    // is readable by every process and every account on that host, not only by the entity meant
    // to receive it - no parser hardening in front of it changes that.
  }


  private static String randomMarker() {
    byte[] marker = new byte[8];
    new SecureRandom().nextBytes(marker);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(marker);
  }

  @PostMapping(path = "xxe/blind", consumes = ALL_VALUE, produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult addComment(
      @RequestBody String commentStr, @AuthenticationPrincipal WebGoatUser user) {
    var fileContentsForUser = userToFileContents.getOrDefault(user, "");

    // Handing this value back is not proof of anything any more: the only way to have obtained it
    // was to make the parser resolve an external entity and post the result, and that path is
    // closed. Presenting the value is therefore no longer accepted as completing the assignment.

    try {
      Comment comment = comments.parseXml(commentStr);
      if (fileContentsForUser.contains(comment.getText())) {
        comment.setText("Nice try, you need to send the file to WebWolf");
      }
      comments.addComment(comment, user, false);
    } catch (Exception e) {
      return failed(this).output(e.toString()).build();
    }
    return failed(this).build();
  }

  @Override
  public void initialize(WebGoatUser user) {
    comments.reset(user);
    userToFileContents.remove(user);
    createSecretFileWithRandomContents(user);
  }
}
