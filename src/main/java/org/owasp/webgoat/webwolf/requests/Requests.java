/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller for fetching all the HTTP requests from WebGoat to WebWolf for a specific user.
 *
 * @author nbaars
 * @since 8/13/17.
 */
@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(value = "/requests")
public class Requests {

  private final WebWolfTraceRepository traceRepository;
  private final ObjectMapper objectMapper;

  @AllArgsConstructor
  @Getter
  private class Tracert {
    private final Instant date;
    private final String path;
    private final String json;
  }

  @GetMapping
  public ModelAndView get(Authentication authentication) {
    var model = new ModelAndView("requests");
    String username = (null != authentication) ? authentication.getName() : "anonymous";
    var traces =
        traceRepository.findAll().stream()
            .filter(t -> allowedTrace(t, username))
            .map(t -> new Tracert(t.getTimestamp(), path(t), toJsonString(t)))
            .toList();
    model.addObject("traces", traces);

    return model;
  }

  /**
   * Decides whether a recorded request may be shown to the user asking for this page.
   *
   * <p>This used to start from "allowed" and take away the two paths somebody had thought of. Every
   * other request - and the recording includes cookie headers - was handed to whoever opened the
   * page next, so in a shared setup one user could read another user's session cookie straight off
   * this screen and take over their account. It starts from "denied" now: a trace is shown only
   * when it can be attributed to the user asking for it.
   */
  private boolean allowedTrace(HttpExchange t, String username) {
    HttpExchange.Request req = t.getRequest();
    String path = req.getUri().getPath();
    String query = req.getUri().getQuery();

    if (path.contains("/files")) {
      return isUserFileRequest(req, username);
    }
    if (path.contains("/landing")) {
      return query != null && query.contains(username);
    }
    return false;
  }

  private boolean isUserFileRequest(HttpExchange.Request request, String username) {
    String[] pathSegments = request.getUri().getPath().split("/");
    for (int index = 0; index < pathSegments.length - 1; index++) {
      if ("files".equals(pathSegments[index])) {
        return username.equals(pathSegments[index + 1]);
      }
    }
    return false;
  }

  private String path(HttpExchange t) {
    return t.getRequest().getUri().getPath();
  }

  private String toJsonString(HttpExchange t) {
    try {
      return objectMapper.writeValueAsString(t);
    } catch (JsonProcessingException e) {
      log.error("Unable to create json", e);
    }
    return "No request(s) found";
  }
}
