/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Optional;
import org.owasp.webgoat.container.LessonDataSource;

/**
 * Account lookup used by the "input validation" assignments. The account name is bound as a
 * statement parameter, so it is always treated as a value and can never change the structure of the
 * query. That, and not a blacklist of characters or keywords, is what stops SQL injection.
 */
final class UserDataQuery {

  static final String QUERY = "SELECT * FROM user_data WHERE last_name = ?";

  private UserDataQuery() {}

  /** Returns the matching rows as an HTML fragment, or an empty optional when nothing matched. */
  static Optional<String> findUsersByLastName(LessonDataSource dataSource, String lastName)
      throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(QUERY)) {
      statement.setString(1, lastName);
      try (ResultSet results = statement.executeQuery()) {
        if (!results.next()) {
          return Optional.empty();
        }
        return Optional.of(writeTable(results));
      }
    }
  }

  private static String writeTable(ResultSet results) throws SQLException {
    ResultSetMetaData metaData = results.getMetaData();
    int numberOfColumns = metaData.getColumnCount();
    StringBuilder table = new StringBuilder("<p>");
    for (int i = 1; i <= numberOfColumns; i++) {
      table.append(metaData.getColumnName(i)).append(", ");
    }
    table.append("<br />");
    do {
      for (int i = 1; i <= numberOfColumns; i++) {
        table.append(results.getString(i)).append(", ");
      }
      table.append("<br />");
    } while (results.next());
    return table.append("</p>").toString();
  }
}
