/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
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
      return isUserLandingRequest(query, username);
    }
    return false;
  }

  /**
   * A landing request belongs to the user whose name one of its parameters actually is.
   *
   * <p>Testing the raw query string for the name as a substring is not that test. The name is
   * chosen by whoever registers, so a short one is a substring of nearly every query and matches
   * everybody else's traces, which carry the codes and links these lessons hand out. It also
   * matches when the name merely appears inside some unrelated value. Each parameter is decoded
   * and compared on its own instead.
   */
  private boolean isUserLandingRequest(String query, String username) {
    if (query == null || username == null || username.isEmpty()) {
      return false;
    }
    for (String parameter : query.split("&")) {
      int separator = parameter.indexOf('=');
      if (separator < 0) {
        continue;
      }
      // A malformed escape such as "%zz" makes decode throw. Anyone may reach /landing without
      // signing in, so an unguarded call here would let a stranger record one bad trace and take
      // this page down for everybody whose traces sit behind it in the shared queue.
      String raw = parameter.substring(separator + 1);
      String value;
      try {
        value = URLDecoder.decode(raw, StandardCharsets.UTF_8);
      } catch (IllegalArgumentException e) {
        value = raw;
      }
      if (username.equals(value)) {
        return true;
      }
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
