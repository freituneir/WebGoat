/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Accounts were stored with {@code NoOpPasswordEncoder}, which keeps the password in clear text:
 * anybody able to read the user table reads every password. BCrypt applies a salted, deliberately
 * slow hash instead, so the stored value cannot be replayed and does not survive a database dump.
 */
@Configuration
public class PasswordEncoderConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
