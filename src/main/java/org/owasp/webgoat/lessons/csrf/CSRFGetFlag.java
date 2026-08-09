/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
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

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    // This request changes state, so it is only carried out when it proves it was issued by
    // WebGoat itself: the Origin (or Referer) has to match the host we are serving and the
    // per-session anti-CSRF token has to be present. An absent Origin/Referer proves nothing and
    // is rejected instead of trusted.
    if (!CsrfProtection.isSameOrigin(req) || !CsrfProtection.hasValidToken(req)) {
      response.put("success", false);
      response.put("message", "Request rejected, it did not originate from WebGoat");
      response.put("flag", null);
      return response;
    }

    Random random = new Random();
    userSessionData.setValue("csrf-get-success", random.nextInt(65536));
    response.put("success", true);
    response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
    response.put("flag", userSessionData.getValue("csrf-get-success"));

    return response;
  }
}
