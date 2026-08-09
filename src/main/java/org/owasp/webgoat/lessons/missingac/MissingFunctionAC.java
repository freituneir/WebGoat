/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // A salt that is written in the source is not a salt: the user hashes can be recomputed
  // offline by anybody with the repository. Both are drawn at boot, stable for one run.
  public static final String PASSWORD_SALT_SIMPLE = randomSalt();
  public static final String PASSWORD_SALT_ADMIN = randomSalt();

  private static String randomSalt() {
    byte[] salt = new byte[32];
    new SecureRandom().nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
