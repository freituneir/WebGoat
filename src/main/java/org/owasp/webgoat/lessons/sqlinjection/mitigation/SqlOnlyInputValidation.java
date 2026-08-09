/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
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
    value = {"SqlOnlyInputValidation-1", "SqlOnlyInputValidation-2", "SqlOnlyInputValidation-3"})
public class SqlOnlyInputValidation implements AssignmentEndpoint {

  private static final String QUERY = "SELECT * FROM user_data WHERE last_name = ?";

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidation(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidation/attack")
  @ResponseBody
  public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    if (userId.contains(" ")) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    // Blocking a space is not a defence; the value is bound, so it is never parsed as SQL.
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(QUERY)) {
      statement.setString(1, userId);
      try (ResultSet results = statement.executeQuery()) {
        return failed(this).output(renderResults(results)).build();
      }
    } catch (SQLException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private String renderResults(ResultSet results) throws SQLException {
    ResultSetMetaData metaData = results.getMetaData();
    int numberOfColumns = metaData.getColumnCount();
    StringBuilder table = new StringBuilder("<p>");
    boolean headerWritten = false;

    while (results.next()) {
      if (!headerWritten) {
        for (int i = 1; i < (numberOfColumns + 1); i++) {
          table.append(metaData.getColumnName(i));
          table.append(", ");
        }
        table.append("<br />");
        headerWritten = true;
      }
      for (int i = 1; i < (numberOfColumns + 1); i++) {
        table.append(results.getString(i));
        table.append(", ");
      }
      table.append("<br />");
    }

    if (!headerWritten) {
      table.append("No results matched. Try Again.");
    }
    table.append("</p>");
    return table.toString();
  }
}
