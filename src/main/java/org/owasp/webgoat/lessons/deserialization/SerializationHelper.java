/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;

public class SerializationHelper {

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

  /*
   * Reading an object back is where a hostile stream gets to name the classes it wants built, and
   * a gadget's readObject() runs while the graph is still being rebuilt - before any caller can
   * look at what it received. The filter below decides on the type first: only the task holder,
   * strings and primitives are allowed through, everything else is refused.
   */
  private static final ObjectInputFilter EXPECTED_TYPES_ONLY =
      info -> {
        Class<?> type = info.serialClass();
        if (type == null) {
          return ObjectInputFilter.Status.UNDECIDED;
        }
        while (type.isArray()) {
          type = type.getComponentType();
        }
        boolean allowed =
            type.isPrimitive()
                || String.class.equals(type)
                || VulnerableTaskHolder.class.equals(type);
        return allowed ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
      };

  public static Object fromString(String s) throws IOException, ClassNotFoundException {
    byte[] data = Base64.getDecoder().decode(s);
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
      ois.setObjectInputFilter(EXPECTED_TYPES_ONLY);
      return ois.readObject();
    }
  }

  public static String toString(Serializable o) throws IOException {

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(o);
    oos.close();
    return Base64.getEncoder().encodeToString(baos.toByteArray());
  }

  public static String show() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeLong(-8699352886133051976L);
    dos.close();
    byte[] longBytes = baos.toByteArray();
    return bytesToHex(longBytes);
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}
