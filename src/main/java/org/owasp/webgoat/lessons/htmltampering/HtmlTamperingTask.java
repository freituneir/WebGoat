/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.math.BigDecimal;
import java.math.RoundingMode;
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

  /** The catalogue price lives on the server; the browser never gets a say in it. */
  private static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    int quantity;
    try {
      quantity = Integer.parseInt(QTY.trim());
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").output(INVALID_QUANTITY).build();
    }
    if (quantity < 1) {
      return failed(this).feedback("html-tampering.tamper.failure").output(INVALID_QUANTITY).build();
    }

    // Hidden form fields are client-side data. The submitted Total is a display value only: the
    // amount the order is actually booked at is recomputed here from the authoritative unit price
    // and the quantity, so tampering with the hidden field cannot change what is charged.
    BigDecimal total =
        UNIT_PRICE.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);

    return failed(this)
        .feedback("html-tampering.tamper.failure")
        .output("Order recalculated server-side: " + quantity + " x " + UNIT_PRICE + " = " + total)
        .build();
  }

  private static final String INVALID_QUANTITY = "The quantity must be a whole number of items.";
}
