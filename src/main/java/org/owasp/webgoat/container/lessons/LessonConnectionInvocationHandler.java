/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which sets the correct schema for the currently bounded user. This way users are not
 * seeing each other data, and we can reset data for just one particular user.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

  private final Connection targetConnection;

  public LessonConnectionInvocationHandler(Connection targetConnection) {
    this.targetConnection = targetConnection;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.getPrincipal() instanceof WebGoatUser user) {
      try (var statement = targetConnection.createStatement()) {
        statement.execute("SET SCHEMA " + quotedSchema(user.getUsername()));
      }
    }
    try {
      return method.invoke(targetConnection, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }

  /**
   * A schema name cannot be bound as a parameter, so it is quoted here instead. The name comes from
   * the account, and an account name is chosen by whoever registers it: one containing a double
   * quote used to end the identifier early and let the rest of the name run on as SQL of its own.
   * Doubling the quotes keeps the whole name inside the identifier, whatever it contains.
   */
  private String quotedSchema(String username) {
    return "\"" + username.replace("\"", "\"\"") + "\"";
  }
}
