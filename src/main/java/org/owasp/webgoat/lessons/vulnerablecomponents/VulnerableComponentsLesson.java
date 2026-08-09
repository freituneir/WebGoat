/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import java.io.StringReader;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  private static final String ROOT_ELEMENT = "contact";
  private static final List<String> CONTACT_FIELDS =
      List.of("id", "firstName", "lastName", "email");

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    // Deny everything, then name the single type this lesson is allowed to build. Without this
    // the mapping library decides from the document which classes to instantiate, which is the
    // whole mechanism behind the remote code execution issues reported against it.
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(NullPermission.NULL);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    xstream.allowTypes(new Class[] {ContactImpl.class, String.class, Integer.class});
    Contact contact = null;

    try {
      String submitted =
          payload
              .replace("+", "")
              .replace("\r", "")
              .replace("\n", "")
              .replace("> ", ">")
              .replace(" <", "<");
      /*
       * What the caller sent never reaches XStream. Only a document this class assembled itself
       * does, so the request cannot pick the classes that get instantiated.
       */
      contact = (Contact) xstream.fromXML(rebuildContactDocument(submitted));
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger the example like
        // https://x-stream.github.io/CVE-2013-7285.html
      }
      if (null != contact && !(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      return success(this).feedback("vulnerable-components.success").output(e.getMessage()).build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }

  /*
   * Parses what came in with a parser that resolves nothing, keeps the plain values of a contact
   * and writes them into a document built from scratch. Everything XStream could use to choose a
   * class of its own - type attributes, dynamic proxies, unexpected or nested elements, a doctype
   * - is refused or simply not carried over.
   */
  private String rebuildContactDocument(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    Element root = builder.parse(new InputSource(new StringReader(payload))).getDocumentElement();

    if (root == null || !ROOT_ELEMENT.equals(root.getNodeName()) || root.hasAttributes()) {
      throw new IllegalArgumentException("Only a plain " + ROOT_ELEMENT + " document is accepted");
    }

    StringBuilder document = new StringBuilder("<").append(ROOT_ELEMENT).append(">");
    NodeList children = root.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (child.getNodeType() != Node.ELEMENT_NODE) {
        continue;
      }
      String name = child.getNodeName();
      if (!CONTACT_FIELDS.contains(name) || child.hasAttributes() || hasChildElements(child)) {
        throw new IllegalArgumentException("Unexpected element: " + name);
      }
      document.append("<").append(name).append(">");
      document.append(xmlEscape(child.getTextContent()));
      document.append("</").append(name).append(">");
    }
    return document.append("</").append(ROOT_ELEMENT).append(">").toString();
  }

  private boolean hasChildElements(Node node) {
    NodeList children = node.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
        return true;
      }
    }
    return false;
  }

  private String xmlEscape(String value) {
    if (value == null) {
      return "";
    }
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
