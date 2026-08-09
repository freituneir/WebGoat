/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.httpproxies;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HttpBasicsInterceptRequest implements AssignmentEndpoint {

  @RequestMapping(
      path = "/HttpProxies/intercept-request",
      method = {RequestMethod.POST, RequestMethod.GET})
  @ResponseBody
  public AttackResult completed(
      @RequestHeader(value = "x-request-intercepted", required = false) Boolean headerValue,
      @RequestParam(value = "changeMe", required = false) String paramValue,
      HttpServletRequest request) {
    // The outcome was recorded on a GET and refused on a POST, so the way to complete the
    // exercise was to change the verb. GET is defined as safe: browsers, proxies and caches may
    // repeat it, prefetch it and replay it from history, and it carries no CSRF token because
    // nothing about it is meant to change state. A request that records a result is not safe, so
    // it has to be the POST the form already sends -- the gate is the same one challenge 8 needed.
    //
    // Interception is still what solves this: the header and the parameter have to be edited in
    // flight, the request simply stays a POST while it happens.
    if (!HttpMethod.POST.matches(request.getMethod())) {
      return failed(this).feedback("http-proxies.intercept.failure").build();
    }
    if (headerValue != null
        && paramValue != null
        && headerValue
        && "Requests are tampered easily".equalsIgnoreCase(paramValue)) {
      return success(this).feedback("http-proxies.intercept.success").build();
    } else {
      return failed(this).feedback("http-proxies.intercept.failure").build();
    }
  }
}
