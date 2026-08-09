/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.math.BigDecimal;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final BigDecimal PRICE = new BigDecimal("2999.99");

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    int quantity = quantityOf(QTY);
    if (quantity < 1) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    // The price lives here and the amount owed is recomputed from it. The total the browser
    // posts is ignored, so editing it in the page buys nothing.
    BigDecimal total = PRICE.multiply(BigDecimal.valueOf(quantity));
    return failed(this)
        .feedback("html-tampering.tamper.failure")
        .output("Amount due: $" + total)
        .build();
  }

  private int quantityOf(String qty) {
    try {
      return Integer.parseInt(qty.trim());
    } catch (NumberFormatException e) {
      return 0;
    }
  }
}
