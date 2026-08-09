/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.UUID;
import org.owasp.webgoat.container.session.LessonSession;

/**
 * Indirect object references for the profiles of this lesson.
 *
 * <p>The internal user id is never handed to the client as the reference to a profile. Instead an
 * unguessable reference is issued to the session when the user authenticates, and every request
 * that addresses a profile is resolved back to the user id through that session. A reference that
 * was not issued to the current session resolves to {@code null}, which is the horizontal access
 * control check the profile endpoints enforce.
 */
final class ProfileReferences {

  private static final String AUTHENTICATED_USER_ID = "idor-authenticated-user-id";
  private static final String PROFILE_REFERENCE = "idor-profile-reference";

  private ProfileReferences() {}

  /** Issues a fresh reference for the profile of the user that just authenticated. */
  static String issue(LessonSession session) {
    String reference = UUID.randomUUID().toString();
    session.setValue(PROFILE_REFERENCE, reference);
    return reference;
  }

  /** Returns the reference issued to this session, or {@code null} when there is none. */
  static String current(LessonSession session) {
    return (String) session.getValue(PROFILE_REFERENCE);
  }

  /**
   * Resolves a client supplied reference to the user id it was issued for.
   *
   * @return the authenticated user id, or {@code null} when the caller does not own the referenced
   *     profile
   */
  static String resolve(LessonSession session, String reference) {
    String issued = current(session);
    String userId = (String) session.getValue(AUTHENTICATED_USER_ID);
    if (issued == null || userId == null || reference == null || !issued.equals(reference)) {
      return null;
    }
    return userId;
  }
}
