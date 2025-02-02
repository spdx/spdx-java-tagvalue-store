/**
 * SPDX-FileCopyrightText: Copyright (c) 2017 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 * <p>
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * <p>
 *       https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
