/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
      "SqlStringInjectionHint-mitigation-10b-1",
      "SqlStringInjectionHint-mitigation-10b-2",
      "SqlStringInjectionHint-mitigation-10b-3",
      "SqlStringInjectionHint-mitigation-10b-4",
      "SqlStringInjectionHint-mitigation-10b-5"
    })
public class SqlInjectionLesson10b implements AssignmentEndpoint {

  @PostMapping("/SqlInjectionMitigations/attack10b")
  @ResponseBody
  public AttackResult completed(@RequestParam String editor) {
    try {
      if (editor.isEmpty()) return failed(this).feedback("sql-injection.10b.no-code").build();

      editor = editor.replaceAll("\\<.*?>", "");

      String regexSetsUpConnection = "(?=.*getConnection.*)";
      String regexUsesPreparedStatement = "(?=.*PreparedStatement.*)";
      String regexUsesPlaceholder = "(?=.*\\=\\?.*|.*\\=\\s\\?.*)";
      String regexUsesSetString = "(?=.*setString.*)";
      String regexUsesExecute = "(?=.*execute.*)";
      String regexUsesExecuteUpdate = "(?=.*executeUpdate.*)";

      String codeline = editor.replace("\n", "").replace("\r", "");

      boolean setsUpConnection = this.check_text(regexSetsUpConnection, codeline);
      boolean usesPreparedStatement = this.check_text(regexUsesPreparedStatement, codeline);
      boolean usesSetString = this.check_text(regexUsesSetString, codeline);
      boolean usesPlaceholder = this.check_text(regexUsesPlaceholder, codeline);
      boolean usesExecute = this.check_text(regexUsesExecute, codeline);
      boolean usesExecuteUpdate = this.check_text(regexUsesExecuteUpdate, codeline);

      boolean hasImportant =
          (setsUpConnection
              && usesPreparedStatement
              && usesPlaceholder
              && usesSetString
              && (usesExecute || usesExecuteUpdate));
      // The submission used to be wrapped in a class and handed to the JDK compiler at runtime.
      // Compiling source that arrived with a request lets a caller decide what the server turns
      // into bytecode, writes .class files of their choosing to disk and, with an annotation
      // processor on the classpath, runs their code outright. The answer is inspected as text.
      if (hasImportant) {
        return success(this).feedback("sql-injection.10b.success").build();
      } else {
        return failed(this).feedback("sql-injection.10b.failed").build();
      }
    } catch (Exception e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private boolean check_text(String regex, String text) {
    Pattern p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher m = p.matcher(text);
    if (m.find()) return true;
    else return false;
  }
}
