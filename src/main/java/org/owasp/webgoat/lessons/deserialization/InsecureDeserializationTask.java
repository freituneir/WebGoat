/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask implements AssignmentEndpoint {

  /*
   * A hostile stream never gets to name a class. Only primitives and strings are let through,
   * anything else is refused before an instance exists, so no gadget's readObject() ever runs.
   */
  private static final ObjectInputFilter DATA_ONLY_FILTER =
      info -> {
        Class<?> clazz = info.serialClass();
        if (clazz == null) {
          return ObjectInputFilter.Status.UNDECIDED;
        }
        while (clazz.isArray()) {
          clazz = clazz.getComponentType();
        }
        if (clazz.isPrimitive() || String.class.equals(clazz)) {
          return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
      };

  @PostMapping("/InsecureDeserialization/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String token) throws IOException {
    String b64token;
    long before;
    long after;
    int delay;

    b64token = token.replace('-', '+').replace('_', '/');

    try (ObjectInputStream ois = new GuardedObjectInputStream(b64token)) {
      before = System.currentTimeMillis();
      Object o = ois.readObject();
      if (!(o instanceof VulnerableTaskHolder)) {
        if (o instanceof String) {
          return failed(this).feedback("insecure-deserialization.stringobject").build();
        }
        return failed(this).feedback("insecure-deserialization.wrongobject").build();
      }
      after = System.currentTimeMillis();
    } catch (InvalidClassException e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    } catch (IllegalArgumentException e) {
      return failed(this).feedback("insecure-deserialization.expired").build();
    } catch (Exception e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    }

    delay = (int) (after - before);
    if (delay > 7000) {
      return failed(this).build();
    }
    if (delay < 3000) {
      return failed(this).build();
    }
    return success(this).build();
  }

  /*
   * Belt and braces: the stream itself declines to resolve any class or proxy, so the guard does
   * not rest on the filter alone. A plain string carries no class descriptor and still reads back,
   * which keeps this assignment's feedback working.
   */
  private static final class GuardedObjectInputStream extends ObjectInputStream {

    private GuardedObjectInputStream(String b64token) throws IOException {
      super(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)));
      setObjectInputFilter(DATA_ONLY_FILTER);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws InvalidClassException {
      throw new InvalidClassException(desc.getName(), "class is not accepted");
    }

    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws InvalidClassException {
      throw new InvalidClassException("proxies are not accepted");
    }
  }
}
