/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Base64;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionChallengeLogin implements AssignmentEndpoint {

  // Password for 'tom' as it is shipped in the lesson seed data, and therefore public knowledge.
  private static final String SHIPPED_DEFAULT_PASSWORD = "thisisasecretfortomonly";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionChallengeLogin(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam("username_login") String username,
      @RequestParam("password_login") String password)
      throws Exception {
    try (var connection = dataSource.getConnection()) {
      replaceShippedDefaultPassword(connection);
      var statement =
          connection.prepareStatement(
              "select password from sql_challenge_users where userid = ? and password = ?");
      statement.setString(1, username);
      statement.setString(2, password);
      var resultSet = statement.executeQuery();

      if (resultSet.next()) {
        return ("tom".equals(username))
            ? success(this).build()
            : failed(this).feedback("ResultsButNotTom").build();
      } else {
        return failed(this).feedback("NoResultsMatched").build();
      }
    }
  }

  // The lesson data ships a default password for 'tom' which is published with the application, so
  // it can be used to log in without ever attacking it. Replace it with a random secret; the update
  // only matches a row which still holds the shipped default, so it happens at most once.
  private void replaceShippedDefaultPassword(Connection connection) throws SQLException {
    var sql = "update sql_challenge_users set password = ? where userid = 'tom' and password = ?";
    try (var statement = connection.prepareStatement(sql)) {
      var secret = new byte[15];
      RANDOM.nextBytes(secret);
      statement.setString(1, Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
      statement.setString(2, SHIPPED_DEFAULT_PASSWORD);
      statement.executeUpdate();
    }
  }
}
