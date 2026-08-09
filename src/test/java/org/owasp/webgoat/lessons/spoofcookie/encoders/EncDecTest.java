/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class EncDecTest {

  @ParameterizedTest
  @DisplayName("A cookie this application issued decodes back to the name it was issued for")
  @ValueSource(strings = {"webgoat", "admin", "tom"})
  void encodeThenDecodeRoundTrips(String username) {
    assertThat(EncDec.decode(EncDec.encode(username))).isEqualTo(username);
  }

  @Test
  @DisplayName("A payload swapped onto somebody else's signature is rejected")
  void tamperedPayloadIsRejected() {
    String forgedPayload = EncDec.encode("tom").split("\\.")[0];
    String borrowedSignature = EncDec.encode("webgoat").split("\\.")[1];

    assertThatThrownBy(() -> EncDec.decode(forgedPayload + "." + borrowedSignature))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("A value that carries no signature at all is rejected")
  void unsignedValueIsRejected() {
    assertThatThrownBy(() -> EncDec.decode("dG9t")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("A cookie in the old, merely-encoded format is rejected")
  void legacyEncodedCookieIsRejected() {
    assertThatThrownBy(() -> EncDec.decode("NjI2MTcwNGI3YTQxNGE1OTU2NzQ2ZDZmNzQ="))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("null encode test")
  void testNullEncode() {
    assertThat(EncDec.encode(null)).isNull();
  }

  @Test
  @DisplayName("null decode test")
  void testNullDecode() {
    assertThat(EncDec.decode(null)).isNull();
  }
}
