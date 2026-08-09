/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.SQLException;
import java.util.Optional;
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
      "SqlOnlyInputValidationOnKeywords-1",
      "SqlOnlyInputValidationOnKeywords-2",
      "SqlOnlyInputValidationOnKeywords-3"
    })
public class SqlOnlyInputValidationOnKeywords implements AssignmentEndpoint {

  private static final String YOUR_QUERY_WAS = "<br> Your query was: " + UserDataQuery.QUERY;

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidationOnKeywords(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidationOnKeywords/attack")
  @ResponseBody
  public AttackResult attack(
      @RequestParam("userid_sql_only_input_validation_on_keywords") String userId) {
    // Stripping keywords out of the input cannot work: the stripping itself re-creates them
    // (SESELECTLECT -> SELECT). The account name is bound as a parameter instead.
    try {
      Optional<String> users = UserDataQuery.findUsersByLastName(dataSource, userId);
      if (users.isEmpty()) {
        return failed(this).output("No results matched. Try Again." + YOUR_QUERY_WAS).build();
      }
      return failed(this).output(users.get() + YOUR_QUERY_WAS).build();
    } catch (SQLException e) {
      return failed(this).output(e.getMessage() + YOUR_QUERY_WAS).build();
    }
  }
}
