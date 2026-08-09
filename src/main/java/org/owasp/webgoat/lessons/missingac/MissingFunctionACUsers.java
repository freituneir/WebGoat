/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/** Created by jason on 1/5/17. */
@Controller
@AllArgsConstructor
@Slf4j
public class MissingFunctionACUsers {

  private final MissingAccessControlUserRepository userRepository;

  @GetMapping(path = {"access-control/users"})
  public ModelAndView listUsers(@CurrentUsername String username) {

    ModelAndView model = new ModelAndView();
    model.setViewName("list_users");
    // display objects instead of the entities themselves, and only for an administrator
    List<DisplayUser> displayUsers = new ArrayList<>();
    if (hasAdminRole(username)) {
      for (User user : userRepository.findAllUsers()) {
        displayUsers.add(new DisplayUser(user, PASSWORD_SALT_SIMPLE));
      }
    }
    model.addObject("numUsers", displayUsers.size());
    model.addObject("allUsers", displayUsers);

    return model;
  }

  @GetMapping(
      path = {"access-control/users"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersService(@CurrentUsername String username) {
    if (!hasAdminRole(username)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    return ResponseEntity.ok(
        userRepository.findAllUsers().stream()
            .map(user -> new DisplayUser(user, PASSWORD_SALT_SIMPLE))
            .collect(Collectors.toList()));
  }

  @GetMapping(
      path = {"access-control/users-admin-fix"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersFixed(@CurrentUsername String username) {
    if (hasAdminRole(username)) {
      return ResponseEntity.ok(
          userRepository.findAllUsers().stream()
              .map(user -> new DisplayUser(user, PASSWORD_SALT_ADMIN))
              .collect(Collectors.toList()));
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  @PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<User> addUser(
      @RequestBody User newUser, @CurrentUsername String username) {
    if (!hasAdminRole(username)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    try {
      userRepository.save(newUser);
      return ResponseEntity.ok(newUser);
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }

  private boolean hasAdminRole(String username) {
    if (username == null) {
      return false;
    }
    var currentUser = userRepository.findByUsername(username);
    return currentUser != null && currentUser.isAdmin();
  }
}
