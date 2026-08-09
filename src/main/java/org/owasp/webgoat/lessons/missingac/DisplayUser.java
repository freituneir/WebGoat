/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  /** Random salts, one per user, generated at runtime and never leaving the server. */
  private static final Map<String, String> SALTS = new ConcurrentHashMap<>();

  private final String username;
  private final boolean admin;

  /** A password hash is not display information, it is never serialized into a response. */
  @JsonIgnore private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // the salt is random and unique per user, so the hash cannot be recomputed from a constant
    String salted = password + saltFor(passwordSalt + username) + username;
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }

  private static String saltFor(String key) {
    return SALTS.computeIfAbsent(key, ignored -> MissingFunctionAC.generateSalt());
  }
}
