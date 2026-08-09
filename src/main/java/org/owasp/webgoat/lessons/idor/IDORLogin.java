/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  /**
   * Passwords are never kept in plaintext, only as a salted adaptive hash. Tom's password is the
   * one published in the lesson text (IDOR_login.adoc); Bill is not a login account here, so his
   * password is a random value that is not published anywhere.
   */
  private static final String TOM_PASSWORD_HASH =
      "$2a$10$vSeh/aLAVe6UGJyXzN1E4urtpYAZxVyIT.eOiCajLjqD/FH5tWchG";

  private static final String BILL_PASSWORD_HASH =
      "$2a$10$7yOOqno8XejRXRMg8eO7VOZNS326TnK4gMh4ASESPBIBuLuh09vQm";

  private final LessonSession lessonSession;
  private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  private final Map<String, Map<String, String>> idorUserInfo = new HashMap<>();

  public void initIDORInfo() {

    idorUserInfo.put("tom", new HashMap<String, String>());
    idorUserInfo.get("tom").put("passwordHash", TOM_PASSWORD_HASH);
    idorUserInfo.get("tom").put("id", "2342384");
    idorUserInfo.get("tom").put("color", "yellow");
    idorUserInfo.get("tom").put("size", "small");

    idorUserInfo.put("bill", new HashMap<String, String>());
    idorUserInfo.get("bill").put("passwordHash", BILL_PASSWORD_HASH);
    idorUserInfo.get("bill").put("id", "2342388");
    idorUserInfo.get("bill").put("color", "brown");
    idorUserInfo.get("bill").put("size", "large");
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    initIDORInfo();

    Map<String, String> userInfo = idorUserInfo.get(username);
    if (userInfo != null
        && "tom".equals(username)
        && passwordEncoder.matches(password, userInfo.get("passwordHash"))) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", userInfo.get("id"));
      // the profile of the authenticated user is addressed by an indirect reference from here on
      ProfileReferences.issue(lessonSession);
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    return failed(this).feedback("idor.login.failure").build();
  }
}
