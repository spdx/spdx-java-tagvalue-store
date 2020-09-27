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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.model.SpdxDocument;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.ExtendedSpdxStore;
import org.spdx.tag.BuildDocument;
import org.spdx.tag.CommonCode;
import org.spdx.tag.HandBuiltParser;
import org.spdx.tag.InvalidFileFormatException;
import org.spdx.tag.InvalidSpdxTagFileException;
import org.spdx.tag.NoCommentInputStream;
import org.spdx.tag.RecognitionException;

/**
 * SPDX Store implementing serializers and deserializers for the Tag/Value format
 * 
 * @author Gary O'Neall
 *
 */
public class TagValueStore extends ExtendedSpdxStore implements ISerializableModelStore {
	
	List<String> warnings = new ArrayList<String>();

	public TagValueStore(IModelStore baseStore) {
		super(baseStore);
	}

	/* (non-Javadoc)
	 * @see org.spdx.storage.ISerializableModelStore#serialize(java.lang.String, java.io.OutputStream)
	 */
	@Override
	public void serialize(String documentUri, OutputStream stream) throws InvalidSPDXAnalysisException, IOException {
		Properties constants = CommonCode
				.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		SpdxDocument doc = new SpdxDocument(this, documentUri, null, false);
		PrintWriter writer = new PrintWriter(new OutputStreamWriter(
				stream, StandardCharsets.UTF_8), true);
		try {
			CommonCode.printDoc(doc, writer, constants);
		} finally {
			writer.flush();
		}
	}

	/* (non-Javadoc)
	 * @see org.spdx.storage.ISerializableModelStore#deSerialize(java.io.InputStream, boolean)
	 */
	@Override
	public String deSerialize(InputStream stream, boolean overwrite) throws InvalidSPDXAnalysisException, IOException {
		warnings.clear();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		NoCommentInputStream nci = new NoCommentInputStream(stream);
		try{
			HandBuiltParser parser = new HandBuiltParser(nci);
			BuildDocument buildDocument = new BuildDocument(this, constants, warnings);
			parser.setBehavior(buildDocument);
			parser.data();
			return buildDocument.getDocumentUri();
		} catch (RecognitionException e) {
			// error in tag value file
			throw(new InvalidSpdxTagFileException(e.getMessage()));
		} catch (InvalidFileFormatException e) {
			// invalid spdx file format
			throw(new InvalidFileFormatException(e.getMessage()));
		} catch (InvalidSPDXAnalysisException e) {
			throw(e);
		} catch (Exception e){
			// If any other exception - assume this is an RDF/XML file.
			throw(new InvalidSPDXAnalysisException("Unexpected Error: "+e.getMessage(), e));
		}
	}
	
	public List<String> getWarnings() {
		return this.warnings;
	}

}
