/**
 * Copyright (c) 2020 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.tagvaluestore;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.model.SpdxDocument;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.utility.compare.SpdxCompareException;

import junit.framework.TestCase;

/**
 * @author Gary O'Neall
 *
 */
public class TagValueStoreTest extends TestCase {
	
	static final String TAG_VALUE_FILE_PATH = "testResources" + File.separator + "SPDXTagExample-v2.3.spdx";


	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	public void testDeSerialize() throws InvalidSPDXAnalysisException, IOException, SpdxCompareException {
		File tagValueFile = new File(TAG_VALUE_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		String docUri = null;
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			docUri = tvs.deSerialize(tagValueInput, false);
		}
		File testToFile = File.createTempFile("spdx-test", ".spdx");
		try {
			try (OutputStream os = new FileOutputStream(testToFile)) {
				tvs.serialize(docUri, os);
			}
			TagValueStore compareStore = new TagValueStore(new InMemSpdxStore());
			String compDocUri = null;
			try (FileInputStream is = new FileInputStream(testToFile)) {
				compDocUri = compareStore.deSerialize(is, false);
			}
			assertEquals(docUri, compDocUri);
			SpdxDocument doc = new SpdxDocument(tvs, docUri, null, false);
			SpdxDocument compDoc = new SpdxDocument(compareStore, docUri, null, false);
			assertTrue(doc.equivalent(compDoc));
		} finally {
			testToFile.delete();
		}
	}
	
	public void testDeSerializeNoAssertionCopyright() throws InvalidSPDXAnalysisException, IOException, SpdxCompareException {
		File tagValueFile = new File(TAG_VALUE_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		String docUri = null;
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			docUri = tvs.deSerialize(tagValueInput, false);
		}
		try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
			tvs.serialize(docUri, bas);
			String result = bas.toString();
			assertFalse(result.contains("<text>NOASSERTION</text>"));
			assertTrue(result.contains("PackageCopyrightText: NOASSERTION"));
		}
	}

}
