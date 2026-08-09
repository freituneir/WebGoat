/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"crypto-encoding-xor.hints.1"})
public class XOREncodingAssignment implements AssignmentEndpoint {

  /*
   * The database password sat in this file, and the lesson published it as a reversible {xor}
   * value on top of that. It is generated per run now, so undoing the published encoding no
   * longer yields a credential that works anywhere.
   */
  private static final String DB_PASSWORD = randomPassword();

  private static String randomPassword() {
    byte[] password = new byte[24];
    new SecureRandom().nextBytes(password);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(password);
  }

  @PostMapping("/crypto/encoding/xor")
  @ResponseBody
  public AttackResult completed(@RequestParam String answer_pwd1) {
    if (answer_pwd1 != null && answer_pwd1.equals(DB_PASSWORD)) {
      return success(this).feedback("crypto-encoding-xor.success").build();
    }
    return failed(this).feedback("crypto-encoding-xor.empty").build();
  }
}
