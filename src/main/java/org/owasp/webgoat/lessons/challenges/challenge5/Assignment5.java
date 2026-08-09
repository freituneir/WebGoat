/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class Assignment5 implements AssignmentEndpoint {

  // Every account seeded by V2018_09_26_1__users.sql, each of which ships a plaintext password.
  private static final List<String> SEEDED_USERS = List.of("larry", "tom", "alice", "eve");
  private static final SecureRandom RANDOM = new SecureRandom();

  private final AtomicBoolean credentialsRotated = new AtomicBoolean(false);

  private final LessonDataSource dataSource;
  private final Flags flags;

  @PostMapping("/challenge/5")
  @ResponseBody
  public AttackResult login(
      @RequestParam String username_login, @RequestParam String password_login) throws Exception {
    if (!StringUtils.hasText(username_login) || !StringUtils.hasText(password_login)) {
      return failed(this).feedback("required4").build();
    }
    if (!"Larry".equals(username_login)) {
      return failed(this).feedback("user.not.larry").feedbackArgs(username_login).build();
    }
    try (var connection = dataSource.getConnection()) {
      rotateShippedPasswords(connection);
      PreparedStatement statement =
          connection.prepareStatement(
              "select password from challenge_users where userid = ? and password = ?");
      statement.setString(1, username_login);
      statement.setString(2, password_login);
      ResultSet resultSet = statement.executeQuery();

      if (resultSet.next()) {
        return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(5)).build();
      } else {
        return failed(this).feedback("challenge.close").build();
      }
    }
  }

  // The seed data for this challenge ships every account's password in the repository, so the
  // published values are credentials anyone can read. Each account is given its own freshly
  // generated one, which means knowing what the migration file says no longer opens an account.
  //
  // The rotation runs once per boot. Re-running it per request would rewrite the row between the
  // caller reading a password and presenting it, so no credential could ever match -- and it would
  // write to the table on every unauthenticated request.
  private void rotateShippedPasswords(Connection connection) {
    if (!credentialsRotated.compareAndSet(false, true)) {
      return;
    }
    try (PreparedStatement statement =
        connection.prepareStatement("update challenge_users set password = ? where userid = ?")) {
      for (String userid : SEEDED_USERS) {
        statement.setString(1, randomPassword());
        statement.setString(2, userid);
        statement.addBatch();
      }
      statement.executeBatch();
    } catch (SQLException e) {
      // leave the stored values alone, and let the next attempt try again
      credentialsRotated.set(false);
    }
  }

  private static String randomPassword() {
    byte[] secret = new byte[16];
    RANDOM.nextBytes(secret);
    return HexFormat.of().formatHex(secret);
  }
}
