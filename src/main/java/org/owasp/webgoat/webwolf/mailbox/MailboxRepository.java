/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public interface MailboxRepository extends JpaRepository<Email, String> {

  List<Email> findByRecipientOrderByTimeDesc(String recipient);

  @Transactional
  void deleteByRecipient(String recipient);
}
