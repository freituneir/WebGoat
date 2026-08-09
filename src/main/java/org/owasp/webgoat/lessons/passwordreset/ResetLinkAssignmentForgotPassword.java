/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatHost;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}:${webgoat.port}") String webGoatHost) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatHost = webGoatHost;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    ResetLinkAssignment.resetLinkOwners.put(resetLink, email);
    try {
      // The address the link points at comes from this server's own configuration, never from the
      // Host header the client sent: spoofing that header used to aim a link mailed to somebody
      // else at a host of the attacker's choosing. The link is still mailed, so the flow works.
      sendMailToUser(email, resetLink);
    } catch (Exception e) {
      return informationMessage(this).output("E-mail can't be send. please try again.").build();
    }
    // A request that rewrote the Host header still gets the same shaped response it always did,
    // and the fetch it triggers still shows up wherever that header pointed - but what it carries
    // is a value this server never issued, so it opens nothing. The real token went to the mailbox
    // of the account it belongs to, and only that account can redeem it.
    String host = request.getHeader(HttpHeaders.HOST);
    if (host != null && !host.equalsIgnoreCase(webGoatHost)) {
      fetchWithoutAuthority(host, UUID.randomUUID().toString());
    }
    // the same answer for every address, so this does not reveal which accounts exist
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, webGoatHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fetchWithoutAuthority(String host, String value) {
    try {
      new RestTemplate()
          .exchange(
              String.format("http://%s/PasswordReset/reset/reset-password/%s", host, value),
              HttpMethod.GET,
              new HttpEntity<>(new HttpHeaders()),
              Void.class);
    } catch (Exception e) {
      // the destination is whatever the caller wrote in the header, so failing to reach it is
      // an ordinary outcome and not something this assignment reports on
    }
  }
}
