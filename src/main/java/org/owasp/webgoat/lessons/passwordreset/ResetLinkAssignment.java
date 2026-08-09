/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
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
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static final String PASSWORD_TOM_9 =
      "somethingVeryRandomWhichNoOneWillEverTypeInAsPasswordForTom";
  static List<String> resetLinks = new CopyOnWriteArrayList<>();
  static Map<String, String> resetLinkOwners = new ConcurrentHashMap<>();
  static Map<String, String> passwordsByEmail = new ConcurrentHashMap<>();

  // The mail still carries a working reset link — that is the flow this lesson teaches. What it no
  // longer carries is an address the requester chose: the host comes from this server's own
  // configuration, so spoofing the Host header cannot aim somebody else's link at a machine the
  // attacker controls, and the link is only ever delivered to the mailbox of the account it was
  // issued for.
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
  public AttackResult login(@RequestParam String password, @RequestParam String email) {
    // A password only exists here once the owner of that mailbox redeemed the link that was
    // delivered to it. Holding a link issued for somebody else never gets an entry in this map,
    // so this answers the ordinary "wrong password" way rather than by refusing to play.
    String currentPassword = passwordsByEmail.getOrDefault(email, PASSWORD_TOM_9);
    if (!PASSWORD_TOM_9.equals(currentPassword) && currentPassword.equals(password)) {
      return success(this).build();
    }
    return failed(this).feedback(TOM_EMAIL.equals(email) ? "login_failed" : "login_failed.tom")
        .build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(@PathVariable(value = "link") String link, Model model) {
    ModelAndView modelAndView = new ModelAndView();
    if (ResetLinkAssignment.resetLinks.contains(link)) {
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
    // The link belongs to one account. Holding somebody else's link is not enough, only the
    // owner of that account may change its password.
    if (!isOwnedBy(form.getResetLink(), username)) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    // the reset really happens, so the lesson works end to end for the account that owns the link
    passwordsByEmail.put(resetLinkOwners.get(form.getResetLink()), form.getPassword());
    // and it is spent after one use
    resetLinks.remove(form.getResetLink());
    resetLinkOwners.remove(form.getResetLink());
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  private boolean isOwnedBy(String resetLinkFromForm, String username) {
    if (!hasText(resetLinkFromForm) || !hasText(username)) {
      return false;
    }
    String email = resetLinkOwners.get(resetLinkFromForm);
    if (email == null) {
      return false;
    }
    // The mail lands in the mailbox named by the local part of the address, so only the owner of
    // that mailbox may redeem it, whichever domain was typed after the @.
    int index = email.indexOf("@");
    return username.equals(email.substring(0, index == -1 ? email.length() : index));
  }
}
