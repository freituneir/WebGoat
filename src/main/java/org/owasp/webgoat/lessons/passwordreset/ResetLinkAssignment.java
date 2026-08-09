/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import com.google.common.collect.Maps;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  static final String PASSWORD_TOM_9 =
      "somethingVeryRandomWhichNoOneWillEverTypeInAsPasswordForTom";
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static Map<String, String> userToTomResetLink = new HashMap<>();
  static Map<String, String> usersToTomPassword = Maps.newHashMap();
  static List<String> resetLinks = new ArrayList<>();

  /**
   * The address each reset link was issued for. {@link #resetLinks} is shared by every account, so
   * on its own it only answers "is this a link somebody was given", never "was it given to you".
   */
  static Map<String, String> resetLinkOwners = new HashMap<>();

  static final String TEMPLATE =
      """
      Hi, you requested a password reset link, please use this <a target='_blank'
       href='http://%s/WebGoat/PasswordReset/reset/reset-password/%s'>link</a> to reset your
       password.

      If you did not request this password change you can ignore this message.
      If you have any comments or questions, please do not hesitate to reach us at
       support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    if (TOM_EMAIL.equals(email)) {
      String passwordTom = usersToTomPassword.getOrDefault(username, PASSWORD_TOM_9);
      if (passwordTom.equals(PASSWORD_TOM_9)) {
        return failed(this).feedback("login_failed").build();
      } else if (passwordTom.equals(password)) {
        return success(this).build();
      }
    }
    return failed(this).feedback("login_failed.tom").build();
  }

  /**
   * Presenting a reset link now has to be done by the account it was issued for.
   *
   * <p>The only test used to be whether the link appeared in {@link #resetLinks}, and that list is
   * shared by every account in the application. Anyone who came by another user's link — and this
   * lesson hands one out on purpose — could therefore open that user's password-change form and go
   * on to set their password. A reset link is a bearer credential for exactly one account, so it is
   * checked against the account presenting it before anything is rendered.
   */
  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(
      @PathVariable(value = "link") String link, Model model, @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (ResetLinkAssignment.resetLinks.contains(link) && belongsTo(link, username)) {
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(
          VIEW_FORMATTER.formatted("password_reset")); // Display html page for changing password
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword())) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }
    if (!resetLinks.contains(form.getResetLink())
        || !belongsTo(form.getResetLink(), username)) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    if (checkIfLinkIsFromTom(form.getResetLink(), username)) {
      usersToTomPassword.put(username, form.getPassword());
    }
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  /**
   * A link may only be used by the account it was issued for. Links are issued against an e-mail
   * address and accounts are named by the local part of that address, which is how the rest of this
   * lesson already relates the two. A link nobody has claimed ownership of is not usable at all.
   */
  private static boolean belongsTo(String link, String username) {
    String owner = resetLinkOwners.get(link);
    if (owner == null || username == null) {
      return false;
    }
    int index = owner.indexOf("@");
    return username.equals(owner.substring(0, index == -1 ? owner.length() : index));
  }

  private boolean checkIfLinkIsFromTom(String resetLinkFromForm, String username) {
    String resetLink = userToTomResetLink.getOrDefault(username, "unknown");
    return resetLink.equals(resetLinkFromForm);
  }
}
