/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private final String username;
  private final boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  /*
   * This value is handed to administrators over an API, and a plain digest of a password is worth
   * as much as the password to anyone willing to run a word list through the same function. Keying
   * the digest with a secret the server holds means the published value cannot be reproduced off
   * line, so it no longer works as a starting point for recovering the password.
   */
  private static final byte[] HASH_KEY = new byte[32];

  static {
    new SecureRandom().nextBytes(HASH_KEY);
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(HASH_KEY, "HmacSHA256"));
    String salted = password + passwordSalt + username;
    byte[] hash = mac.doFinal(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }
}
