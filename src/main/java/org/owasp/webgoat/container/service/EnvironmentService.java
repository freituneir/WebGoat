/*
 * SPDX-FileCopyrightText: Copyright © 2022 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/environment")
@RequiredArgsConstructor
public class EnvironmentService {

  private final ApplicationContext context;

  /**
   * Where the application keeps its files on disk is not something a client needs to know. Handing
   * out the absolute path tells an attacker the account the process runs as and gives any traversal
   * or upload issue elsewhere a ready-made target to aim at, so the value is no longer returned.
   */
  @GetMapping("/server-directory")
  public ResponseEntity<Void> homeDirectory() {
    return ResponseEntity.notFound().build();
  }
}
