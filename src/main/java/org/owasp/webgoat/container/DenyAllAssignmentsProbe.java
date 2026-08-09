/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Diagnostic probe. Every handler whose return type is an {@link AttackResult} is short circuited
 * with a well formed "not solved" answer, so no assignment in the application can report a result.
 *
 * <p>The reply is a normal 200 with the same JSON shape an assignment produces, so a client that
 * parses it carries on rather than erroring.
 */
@Configuration
public class DenyAllAssignmentsProbe implements WebMvcConfigurer {

  private static final String NOT_SOLVED =
      """
      {"lessonCompleted":false,"feedback":"Sorry the solution is not correct, please try again.",\
      "feedbackArgs":null,"output":null,"outputArgs":null,"assignment":"probe",\
      "attemptWasMade":true}""";

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(
        new HandlerInterceptor() {
          @Override
          public boolean preHandle(
              HttpServletRequest request, HttpServletResponse response, Object handler)
              throws Exception {
            if (handler instanceof HandlerMethod method
                && AttackResult.class.isAssignableFrom(method.getMethod().getReturnType())) {
              response.setStatus(HttpServletResponse.SC_OK);
              response.setContentType(MediaType.APPLICATION_JSON_VALUE);
              response.setCharacterEncoding(StandardCharsets.UTF_8.name());
              response.getWriter().write(NOT_SOLVED);
              response.getWriter().flush();
              return false;
            }
            return true;
          }
        });
  }
}
