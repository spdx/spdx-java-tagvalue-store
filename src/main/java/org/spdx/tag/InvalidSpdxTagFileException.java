/**
 * SPDX-FileContributor: Gary O'Neall
 * SPDX-FileCopyrightText: Copyright (c) 2012 Source Auditor Inc.
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
