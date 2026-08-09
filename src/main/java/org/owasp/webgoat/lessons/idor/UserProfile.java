/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Created by jason on 1/5/17. */
public class UserProfile {

  /**
   * Attributes of a profile that may be disclosed to its owner, in other words the keys returned by
   * {@link #disclosedProfileToMap()}. Internal attributes such as the user id, the role and the
   * admin flag are deliberately not part of this set.
   */
  static final Set<String> DISCLOSED_ATTRIBUTES = Set.of("name", "color", "size");

  private String userId;
  private String name;
  private String color;
  private String size;
  private boolean isAdmin;
  private int role;

  public UserProfile() {}

  public UserProfile(String id) {
    setProfileFromId(id);
  }

  //
  private void setProfileFromId(String id) {
    // emulate look up from database
    if (id.equals("2342384")) {
      this.userId = id;
      this.color = "yellow";
      this.name = "Tom Cat";
      this.size = "small";
      this.isAdmin = false;
      this.role = 3;
    } else if (id.equals("2342388")) {
      this.userId = id;
      this.color = "brown";
      this.name = "Buffalo Bill";
      this.size = "large";
      this.isAdmin = false;
      this.role = 3;
    } else {
      // not found
    }
  }

  /**
   * Serializes only the attributes the owner of the profile is entitled to see. The user id, the
   * role and the admin flag are internal and are never handed to the client.
   */
  public Map<String, Object> disclosedProfileToMap() {
    Map<String, Object> profileMap = new HashMap<>();
    profileMap.put("name", this.name);
    profileMap.put("color", this.color);
    profileMap.put("size", this.size);
    return profileMap;
  }

  public String toHTMLString() {
    String htmlBreak = "<br/>";
    return "userId"
        + this.userId
        + htmlBreak
        + "name"
        + this.name
        + htmlBreak
        + "size"
        + this.size
        + htmlBreak
        + "role"
        + this.role
        + htmlBreak
        + "isAdmin"
        + this.isAdmin;
  }

  //
  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getColor() {
    return color;
  }

  public void setColor(String color) {
    this.color = color;
  }

  public String getSize() {
    return size;
  }

  public void setSize(String size) {
    this.size = size;
  }

  public boolean isAdmin() {
    return isAdmin;
  }

  public void setAdmin(boolean admin) {
    isAdmin = admin;
  }

  public int getRole() {
    return role;
  }

  public void setRole(int role) {
    this.role = role;
  }
}
