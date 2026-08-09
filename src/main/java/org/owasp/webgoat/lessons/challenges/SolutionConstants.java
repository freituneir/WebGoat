/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  // A credential written into the source is public: it sits in the repository, in every build
  // and in every container image. The unguessable part is drawn at boot instead. The "1234"
  // placeholder stays where it is, the challenge still substitutes its pincode there.
  String PASSWORD =
      "!!webgoat_admin_" + java.util.UUID.randomUUID().toString().replace("-", "") + "_1234!!";
}
