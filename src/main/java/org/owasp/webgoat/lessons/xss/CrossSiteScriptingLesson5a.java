/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@AssignmentHints(
    value = {
      "xss-reflected-5a-hint-1",
      "xss-reflected-5a-hint-2",
      "xss-reflected-5a-hint-3",
      "xss-reflected-5a-hint-4"
    })
public class CrossSiteScriptingLesson5a implements AssignmentEndpoint {

  public static final Predicate<String> XSS_PATTERN =
      Pattern.compile(
              ".*<script>(console\\.log|alert)\\(.*\\);?</script>.*", Pattern.CASE_INSENSITIVE)
          .asMatchPredicate();

  private final LessonSession userSessionData;

  public CrossSiteScriptingLesson5a(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @GetMapping("/CrossSiteScripting/attack5a")
  @ResponseBody
  public AttackResult completed(
      @RequestParam Integer QTY1,
      @RequestParam Integer QTY2,
      @RequestParam Integer QTY3,
      @RequestParam Integer QTY4,
      @RequestParam String field1,
      @RequestParam String field2) {

    if (XSS_PATTERN.test(field2)) {
      return failed(this).feedback("xss-reflected-5a-failed-wrong-field").build();
    }

    double totalSale =
        QTY1.intValue() * 69.99
            + QTY2.intValue() * 27.99
            + QTY3.intValue() * 1599.99
            + QTY4.intValue() * 299.99;

    userSessionData.setValue("xss-reflected1-complete", "false");
    // The credit card field is reflected into the HTML of the confirmation page, so it is
    // HTML-encoded here and therefore rendered as text instead of as markup.
    String reflectedField1 = HtmlUtils.htmlEscape(field1);
    StringBuilder cart = new StringBuilder();
    cart.append("Thank you for shopping at WebGoat. <br />Your support is appreciated<hr />");
    cart.append("<p>We have charged credit card:" + reflectedField1 + "<br />");
    cart.append("                             ------------------- <br />");
    cart.append("                               $" + totalSale);

    // init state
    if (userSessionData.getValue("xss-reflected1-complete") == null) {
      userSessionData.setValue("xss-reflected1-complete", "false");
    }

    // The assignment is solved when the page which is sent back really contains an executable
    // script, so the check is done on the reflected response and not on the raw request parameter.
    String response = cart.toString();
    if (XSS_PATTERN.test(response)) {
      userSessionData.setValue("xss-reflected-5a-complete", "true");
      if (response.toLowerCase().contains("console.log")) {
        return success(this).feedback("xss-reflected-5a-success-console").output(response).build();
      } else {
        return success(this).feedback("xss-reflected-5a-success-alert").output(response).build();
      }
    } else {
      userSessionData.setValue("xss-reflected1-complete", "false");
      return failed(this).feedback("xss-reflected-5a-failure").output(response).build();
    }
  }
}
