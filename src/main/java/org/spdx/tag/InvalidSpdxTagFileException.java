/**
 * SPDX-FileCopyrightText: Copyright (c) 2012 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.tag;

import org.spdx.core.InvalidSPDXAnalysisException;

/**
 * Exceptions for errors in a SPDX tag format file
 *
 * @author Gary O'Neall
 */
public class InvalidSpdxTagFileException extends InvalidSPDXAnalysisException {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	/**
	 *
	 */
	public InvalidSpdxTagFileException() {

	}

	/**
	 * @param arg0
	 */
	public InvalidSpdxTagFileException(String arg0) {
		super(arg0);
	}

	/**
	 * @param arg0
	 */
	public InvalidSpdxTagFileException(Throwable arg0) {
		super(arg0);
	}

	/**
	 * @param arg0
	 * @param arg1
	 */
	public InvalidSpdxTagFileException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

}
