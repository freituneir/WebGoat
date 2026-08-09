/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-13-1",
      "SqlStringInjectionHint-mitigation-13-2",
      "SqlStringInjectionHint-mitigation-13-3",
      "SqlStringInjectionHint-mitigation-13-4"
    })
@Slf4j
public class SqlInjectionLesson13 implements AssignmentEndpoint {

  /** The production address as it ships in V2019_09_26_1__servers.sql, and therefore public. */
  private static final String SHIPPED_PRODUCTION_ADDRESS = "104.130.219.202";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionLesson13(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionMitigations/attack12a")
  @ResponseBody
  public AttackResult completed(@RequestParam String ip) {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement preparedStatement =
            connection.prepareStatement("select ip from servers where ip = ? and hostname = ?")) {
      replaceShippedProductionAddress(connection);
      preparedStatement.setString(1, ip);
      preparedStatement.setString(2, "webgoat-prd");
      ResultSet resultSet = preparedStatement.executeQuery();
      if (resultSet.next()) {
        return success(this).build();
      }
      return failed(this).build();
    } catch (SQLException e) {
      log.error("Failed", e);
      return failed(this).build();
    }
  }

  /**
   * The production server's address is the one piece of data this lesson keeps out of the server
   * list, and it ships in the migration script, in the lesson text and in the tests — so it is
   * known to everyone who has the application, with or without an injection. It is replaced here
   * with a per-instance value. The update only matches a row that still holds the shipped address,
   * so it takes effect once and is a no-op afterwards.
   */
  private void replaceShippedProductionAddress(Connection connection) throws SQLException {
    String sql = "UPDATE servers SET ip = ? WHERE hostname = 'webgoat-prd' AND ip = ?";
    try (PreparedStatement statement = connection.prepareStatement(sql)) {
      statement.setString(1, randomAddress());
      statement.setString(2, SHIPPED_PRODUCTION_ADDRESS);
      statement.executeUpdate();
    }
  }

  private static String randomAddress() {
    return (1 + RANDOM.nextInt(223))
        + "."
        + RANDOM.nextInt(256)
        + "."
        + RANDOM.nextInt(256)
        + "."
        + (1 + RANDOM.nextInt(254));
  }
}
