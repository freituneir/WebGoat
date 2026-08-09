/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Lets a caller fetch only the uploads filed under their own name.
 *
 * <p>Uploads are written to {@code <fileLocation>/<username>/} and handed back out by a static
 * resource handler mapped at {@code /files/**}. A resource handler serves whatever sits beneath the
 * location it was given, so requiring a session is not enough on its own: every authenticated
 * caller could read every other caller's uploads simply by naming them, and the upload area is
 * where these lessons park the files an exercise is about. The first path segment after {@code
 * /files/} is the owner, and it has to be the person asking.
 *
 * <p>A request for somebody else's file is answered as if it were not there. Saying "forbidden"
 * would confirm the file exists and so would still disclose the names of other people's uploads.
 */
class UploadOwnershipInterceptor implements HandlerInterceptor {

  private static final String PREFIX = "/files/";

  @Override
  public boolean preHandle(
      HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    String owner = ownerOf(request);
    if (owner != null && owner.equals(currentUsername())) {
      return true;
    }
    response.sendError(HttpServletResponse.SC_NOT_FOUND);
    return false;
  }

  /** The {@code {owner}} in {@code /files/{owner}/{name}}, or null when the shape does not match. */
  private String ownerOf(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String context = request.getContextPath();
    String path = (context != null && !context.isEmpty() && uri.startsWith(context))
        ? uri.substring(context.length())
        : uri;
    if (!path.startsWith(PREFIX)) {
      return null;
    }
    String remainder = path.substring(PREFIX.length());
    int slash = remainder.indexOf('/');
    return slash <= 0 ? null : remainder.substring(0, slash);
  }

  private String currentUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null ? null : authentication.getName();
  }
}
