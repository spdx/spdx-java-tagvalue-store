/**
 * SPDX-FileCopyrightText: Copyright (c) 2011 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.tag;

/**
 * Translates an tag-value file to a an SPDX Document.
 *
 * @author Rana Rahal, Protecode Inc.
 */

public interface TagValueBehavior {
  public void buildDocument(String tag, String value, int lineNumber) throws Exception;
  public void enter() throws Exception;
  public void exit() throws Exception;
}
