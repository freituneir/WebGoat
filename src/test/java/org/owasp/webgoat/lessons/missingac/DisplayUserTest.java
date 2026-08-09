/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", true), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void theHashCannotBeRecomputedFromAConstantInTheSource() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);

    // The value the old, source-derived salt produced for these credentials.
    Assertions.assertThat(displayUser.getUserHash())
        .isNotBlank()
        .isNotEqualTo("cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=");
  }

  @Test
  void everyUserGetsItsOwnSalt() {
    var first = new DisplayUser(new User("user1", "samepassword", false), PASSWORD_SALT_SIMPLE);
    var second = new DisplayUser(new User("user2", "samepassword", false), PASSWORD_SALT_SIMPLE);

    Assertions.assertThat(first.getUserHash()).isNotEqualTo(second.getUserHash());
  }
}
