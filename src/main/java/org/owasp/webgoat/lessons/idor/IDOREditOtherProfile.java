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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null) {
      return failed(this).feedback("idor.view.other.profile.failure1").build();
    }

    // Horizontal access control. Both the id in the path and the id in the body have to be the
    // one of the authenticated user, so no other profile can be reached through this endpoint.
    if (!authUserId.equals(userId)
        || (userSubmittedProfile.getUserId() != null
            && !authUserId.equals(userSubmittedProfile.getUserId()))) {
      return failed(this).feedback("idor.edit.profile.denied").build();
    }

    // What gets written is always the profile of this session, and only the fields a user owns
    // are read from the body. The role decides what somebody may do, so it is not bound from
    // client input (mass assignment).
    UserProfile currentUserProfile = new UserProfile(authUserId);
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    currentUserProfile.setSize(userSubmittedProfile.getSize());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);

    return failed(this)
        .feedback("idor.edit.profile.updated")
        .output(currentUserProfile.profileToMap().toString())
        .build();
  }
}
