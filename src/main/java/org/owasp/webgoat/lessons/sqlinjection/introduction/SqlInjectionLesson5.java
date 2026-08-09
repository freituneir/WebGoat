/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  private static final String NOT_EXECUTED =
      "Free-form SQL is not executed by this endpoint, the input is treated as data only.";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    // Nothing that arrives here is passed to a Statement, so no privilege can be granted
    // through it; only the state the database ended up in is inspected.
    try (Connection connection = dataSource.getConnection()) {
      if (checkSolution(connection)) {
        return success(this).build();
      }
      return failed(this).output(NOT_EXECUTED).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}
