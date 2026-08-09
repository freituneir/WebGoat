/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  // Only somebody who actually read the protected file can know this. It used to be the SHA-512
  // of the user name, which every caller can compute for themselves.
  private final String secretAnswer = UUID.randomUUID().toString();

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    // The answer used to be written to a file next to the pictures this endpoint serves. Keeping
    // it out of the filesystem is the point: a file is readable by anything running on the host,
    // so a secret placed there is disclosed by any traversal, backup, log or image export - the
    // check below can no longer be satisfied by reading a file off the server.
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    // Nothing reachable through this application discloses the answer any more, so a caller that
    // presents it did not get it by using the application as intended.
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    var queryParams = request.getQueryString();
    if (queryParams != null && (queryParams.contains("..") || queryParams.contains("/"))) {
      return ResponseEntity.badRequest()
          .body("Illegal characters are not allowed in the query params");
    }
    try {
      var id = request.getParameter("id");
      var pictureName = (id == null ? String.valueOf(RandomUtils.nextInt(1, 11)) : id) + ".jpg";
      var catPicture = catPictureNamed(pictureName);

      if (catPicture == null) {
        return ResponseEntity.badRequest()
            .body("Illegal characters are not allowed in the query params");
      }
      if (catPicture.exists()) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
          .body(
              StringUtils.arrayToCommaDelimitedString(catPicture.getParentFile().listFiles())
                  .getBytes());
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }

  // Serves only what sits directly in the cat picture directory: the name is reduced to its
  // last segment and the resolved path is checked once symlinks and .. have been resolved.
  private File catPictureNamed(String pictureName) throws IOException {
    var baseDirectory = catPicturesDirectory.getCanonicalFile();
    var picture = new File(baseDirectory, FilenameUtils.getName(pictureName)).getCanonicalFile();
    if (!baseDirectory.equals(picture.getParentFile())) {
      return null;
    }
    return picture;
  }
}
