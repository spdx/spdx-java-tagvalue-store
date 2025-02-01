/**
 * SPDX-FileCopyrightText: Copyright (c) 2017 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.tag;

import org.spdx.core.InvalidSPDXAnalysisException;

/**
 * Exceptions for invalid SPDX file format
 *
 * @author Rohit Lodha
 */
public class InvalidFileFormatException extends InvalidSPDXAnalysisException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 *
	 */
	public InvalidFileFormatException() {
	}

	/**
	 * @param message
	 */
	public InvalidFileFormatException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public InvalidFileFormatException(Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public InvalidFileFormatException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public InvalidFileFormatException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
