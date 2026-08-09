/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Service
public class UserService implements UserDetailsService {

  private UserRepository userRepository;
  private PasswordEncoder passwordEncoder;

  @Autowired
  public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder =
        passwordEncoder == null ? new BCryptPasswordEncoder() : passwordEncoder;
  }

  public UserService(UserRepository userRepository) {
    this(userRepository, new BCryptPasswordEncoder());
  }

  @Override
  public WebWolfUser loadUserByUsername(final String username) throws UsernameNotFoundException {
    WebWolfUser webGoatUser = userRepository.findByUsername(username);
    if (webGoatUser == null) {
      throw new UsernameNotFoundException("User not found");
    }
    webGoatUser.createUser();
    return webGoatUser;
  }

  public void addUser(final String username, final String password) {
    userRepository.save(new WebWolfUser(username, passwordEncoder.encode(password)));
  }
}
