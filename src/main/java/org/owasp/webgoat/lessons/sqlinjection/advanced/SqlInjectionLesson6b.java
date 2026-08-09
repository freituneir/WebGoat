/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {

  // Password for 'dave' as it is shipped in the lesson seed data, and therefore public knowledge.
  private static final String SHIPPED_DEFAULT_PASSWORD = "passW0rD";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    if (userid_6b.equals(getPassword())) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  protected String getPassword() {
    // Fail closed: when the password cannot be read, no submitted value may be accepted.
    String password = null;
    try (Connection connection = dataSource.getConnection()) {
      replaceShippedDefaultPassword(connection);
      String query = "SELECT password FROM user_system_data WHERE user_name = 'dave'";
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results != null && results.first()) {
          password = results.getString("password");
        }
      } catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
    return (password);
  }

  // The lesson data ships a default password for 'dave' which is published with the application,
  // so it is known without ever attacking it. Replace it with a random secret; the update only
  // matches a row which still holds the shipped default, so it happens at most once.
  private void replaceShippedDefaultPassword(Connection connection) throws SQLException {
    String sql =
        "UPDATE user_system_data SET password = ? WHERE user_name = 'dave' AND password = ?";
    try (PreparedStatement statement = connection.prepareStatement(sql)) {
      byte[] secret = new byte[6];
      RANDOM.nextBytes(secret);
      statement.setString(1, Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
      statement.setString(2, SHIPPED_DEFAULT_PASSWORD);
      statement.executeUpdate();
    }
  }
}
