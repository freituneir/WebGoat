/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    try {
      if (!"tom".equals(userSessionData.getValue("idor-authenticated-as"))) {
        return failed(this).feedback("idor.view.own.profile.failure2").build();
      }
      // don't care about http://localhost:8080 ... just want WebGoat/
      String[] urlParts = url.split("/");
      // matching the shape of the Url is not authorization: the last segment is an indirect
      // reference which only resolves to a user id when it was issued to this session
      String authUserId =
          urlParts.length == 4 ? ProfileReferences.resolve(userSessionData, urlParts[3]) : null;
      if (authUserId != null
          && urlParts[0].equals("WebGoat")
          && urlParts[1].equals("IDOR")
          && urlParts[2].equals("profile")) {
        UserProfile userProfile = new UserProfile(authUserId);
        return success(this)
            .feedback("idor.view.own.profile.success")
            .output(userProfile.disclosedProfileToMap().toString())
            .build();
      }
      return failed(this).feedback("idor.view.own.profile.failure1").build();
    } catch (Exception ex) {
      return failed(this).output("an error occurred with your request").build();
    }
  }
}
