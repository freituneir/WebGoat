/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
  };

  /**
   * Retained so the lesson can still describe the class of key that made this forgeable. It is no
   * longer used to sign or to verify anything.
   */
  public static final String JWT_SECRET =
      TextCodec.BASE64.encode(SECRETS[new Random().nextInt(SECRETS.length)]);

  /**
   * The key the server actually trusts. A signing key must have at least as much entropy as the MAC
   * it produces (RFC 7518 §3.2 requires >= 256 bits for HS256), so it is drawn from a CSPRNG at
   * startup and never leaves the process. A dictionary word cannot be substituted for it, which is
   * what made the original token forgeable offline.
   */
  private static final String VERIFICATION_SECRET = generateVerificationSecret();

  private static final String WEBGOAT_USER = "WebGoat";
  private static final List<String> expectedClaims =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");

  private static String generateVerificationSecret() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return Base64.getEncoder().encodeToString(key);
  }

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        // Signed with the same high-entropy key the server verifies with. The token this hands
        // out is therefore no longer crackable offline: an HS256 key drawn from a dictionary can
        // be recovered from any captured token in seconds, which is what let anyone re-sign it
        // with whatever claims they liked.
        .signWith(SignatureAlgorithm.HS256, VERIFICATION_SECRET)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jwt jwt = Jwts.parser().setSigningKey(VERIFICATION_SECRET).parseClaimsJws(token);
      Claims claims = (Claims) jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      } else {
        String user = (String) claims.get("username");

        if (WEBGOAT_USER.equalsIgnoreCase(user)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
        }
      }
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
  }
}
