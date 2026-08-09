/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@RequestMapping("/clientSideFiltering/challenge-store")
public class ShopEndpoint {

  @AllArgsConstructor
  private class CheckoutCodes {

    @Getter private List<CheckoutCode> codes;

    public Optional<CheckoutCode> get(String code) {
      return codes.stream().filter(c -> c.getCode().equals(code)).findFirst();
    }
  }

  @AllArgsConstructor
  @Getter
  private class CheckoutCode {
    private String code;
    private int discount;
  }

  private CheckoutCodes checkoutCodes;

  public ShopEndpoint() {
    List<CheckoutCode> codes = Lists.newArrayList();
    codes.add(new CheckoutCode("webgoat", 25));
    codes.add(new CheckoutCode("owasp", 25));
    codes.add(new CheckoutCode("owasp-webgoat", 50));
    this.checkoutCodes = new CheckoutCodes(codes);
  }

  @GetMapping(value = "/coupons/{code}", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCode getDiscountCode(@PathVariable String code) {
    if (ClientSideFilteringFreeAssignment.SUPER_COUPON_CODE.equals(code)) {
      return new CheckoutCode(ClientSideFilteringFreeAssignment.SUPER_COUPON_CODE, 100);
    }
    return checkoutCodes.get(code).orElse(new CheckoutCode("no", 0));
  }

  @GetMapping(value = "/coupons", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCodes all() {
    // Filtering happens here, on the server. The response carries only the coupons the shop is
    // willing to advertise; hiding a privileged code in the payload and trusting the page not to
    // render it is not a control, because the raw JSON is always readable by the client.
    return new CheckoutCodes(Lists.newArrayList(this.checkoutCodes.getCodes()));
  }
}
