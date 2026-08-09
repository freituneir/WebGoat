/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDORViewOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDORViewOtherProfile(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @GetMapping(
      path = "/IDOR/profile/{userId}",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@PathVariable("userId") String userId) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null) {
      return failed(this).feedback("idor.view.other.profile.failure1").build();
    }

    // Horizontal access control. An id out of the request is only followed when it is the id of
    // the authenticated user, so counting or fuzzing through them discloses nothing. The reply
    // reads the same whether or not the profile that was asked for exists.
    if (!authUserId.equals(userId)) {
      return failed(this).feedback("idor.view.profile.denied").build();
    }

    UserProfile requestedProfile = new UserProfile(authUserId);
    return failed(this)
        .feedback("idor.view.profile.own")
        .output(requestedProfile.profileToMap().toString())
        .build();
  }
}
