/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.NoSuchAlgorithmException;
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
@AssignmentHints({
  "crypto-secure-defaults.hints.1",
  "crypto-secure-defaults.hints.2",
  "crypto-secure-defaults.hints.3"
})
public class SecureDefaultsAssignment implements AssignmentEndpoint {

  /*
   * The expected digest was a constant in this file, so the answer was public. It is computed
   * from a value drawn at boot instead, which is the point the lesson is trying to make.
   */
  private static final String SECRET = randomSecret();

  private static String randomSecret() {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
  }

  @PostMapping("/crypto/secure/defaults")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String secretFileName, @RequestParam String secretText)
      throws NoSuchAlgorithmException {
    if (secretFileName != null && secretFileName.equals("default_secret")) {
      if (secretText != null
          && HashingAssignment.getHash(secretText, "SHA-256")
              .equalsIgnoreCase(HashingAssignment.getHash(SECRET, "SHA-256"))) {
        return success(this).feedback("crypto-secure-defaults.success").build();
      } else {
        return failed(this).feedback("crypto-secure-defaults.messagenotok").build();
      }
    }
    return failed(this).feedback("crypto-secure-defaults.notok").build();
  }
}
