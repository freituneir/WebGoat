/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  private final SecureRandom random = new SecureRandom();

  /**
   * Carries out a state changing request and hands back the flag that proves it happened.
   *
   * <p>Originally the reward was inverted: the flag was issued precisely when the request came from
   * another site, or carried no {@code Referer} at all, and was withheld when it genuinely came
   * from WebGoat. That is the vulnerability — a page on any other origin could make the victim's
   * browser perform this action and read the result back.
   *
   * <p>The decision is now the standard one: the request is only honoured when it proves it started
   * here. A cross-site request, and one that will not say where it came from, is refused and gets
   * nothing. A legitimate same-origin request still performs the action and still receives its
   * flag, so the feature itself is intact — only the forged path is closed.
   */
  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    if (!OriginCheck.fromThisApplication(req)) {
      response.put("success", false);
      response.put("message", pluginMessages.getMessage("csrf-request-rejected"));
      response.put("flag", null);
      return response;
    }

    int flag = random.nextInt(65536);
    userSessionData.setValue("csrf-get-success", flag);
    response.put("success", true);
    response.put("message", "Appears the request came from the original host");
    response.put("flag", flag);
    return response;
  }
}
