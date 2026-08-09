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

    // horizontal access control: the reference in the path is resolved against this session, a
    // profile that does not belong to the caller can never be addressed here
    String authUserId = ProfileReferences.resolve(userSessionData, userId);
    if (authUserId == null) {
      return failed(this).feedback("idor.edit.profile.denied").build();
    }

    UserProfile currentUserProfile = new UserProfile(authUserId);
    // bind only the attributes the owner is allowed to change, privileged attributes such as the
    // role, the user id and the admin flag are never taken from the request body
    if (userSubmittedProfile.getColor() != null) {
      currentUserProfile.setColor(userSubmittedProfile.getColor());
    }
    if (userSubmittedProfile.getSize() != null) {
      currentUserProfile.setSize(userSubmittedProfile.getSize());
    }
    // we will persist in the session object for now in case we want to refer back or use it later
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);
    return failed(this)
        .feedback("idor.edit.profile.failure4")
        .output(currentUserProfile.disclosedProfileToMap().toString())
        .build();
  }
}
