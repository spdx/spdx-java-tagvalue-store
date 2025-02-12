/**
 * SPDX-FileContributor: Gary O'Neall
 * SPDX-FileCopyrightText: Copyright (c) 2020 Source Auditor Inc.
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
package org.spdx.tagvaluestore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.annotation.Nullable;

import org.spdx.core.CoreModelObject;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
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
 */
public class TagValueStore extends ExtendedSpdxStore implements ISerializableModelStore {
	
	List<String> warnings = new ArrayList<String>();

	public TagValueStore(IModelStore baseStore) {
		super(baseStore);
	}
	
	@Override
	public void serialize(OutputStream stream) throws InvalidSPDXAnalysisException, IOException {
		serialize(stream, null);
	}

	/* (non-Javadoc)
	 * @see org.spdx.storage.ISerializableModelStore#serialize(java.lang.String, java.io.OutputStream)
	 */
	@Override
	public void serialize(OutputStream stream, @Nullable CoreModelObject modelObject) throws InvalidSPDXAnalysisException, IOException {
		Properties constants = CommonCode
				.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		if (Objects.nonNull(modelObject)) {
			if (modelObject instanceof SpdxDocument) {
				try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
				stream, StandardCharsets.UTF_8), true)) {
					CommonCode.printDoc((SpdxDocument)modelObject, writer, constants);
					writer.flush();
				}
			} else {
				throw new InvalidSPDXAnalysisException("Can not serialize "+modelObject.getClass().toString()+".  Only SpdxDocument is supported");
			}
		} else {
			@SuppressWarnings("unchecked")
			List<SpdxDocument> allDocs = (List<SpdxDocument>)SpdxModelFactory.getSpdxObjects(this, null, 
					SpdxConstantsCompatV2.CLASS_SPDX_DOCUMENT, null, null).collect(Collectors.toList());
			try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
					stream, StandardCharsets.UTF_8), true)) {
				for (SpdxDocument doc:allDocs) {
					CommonCode.printDoc(doc, writer, constants);
				}
				writer.flush();
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.spdx.storage.ISerializableModelStore#deSerialize(java.io.InputStream, boolean)
	 */
	@Override
	public SpdxDocument deSerialize(InputStream stream, boolean overwrite) throws InvalidSPDXAnalysisException, IOException {
		warnings.clear();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		NoCommentInputStream nci = new NoCommentInputStream(stream);
		try{
			HandBuiltParser parser = new HandBuiltParser(nci);
			BuildDocument buildDocument = new BuildDocument(this, constants, warnings);
			parser.setBehavior(buildDocument);
			parser.data();
			String documentUri = buildDocument.getDocumentUri();
			return (SpdxDocument)SpdxModelFactory.inflateModelObject(this, documentUri + "#" + SpdxConstantsCompatV2.SPDX_DOCUMENT_ID, 
					SpdxConstantsCompatV2.CLASS_SPDX_DOCUMENT, new ModelCopyManager(), 
					SpdxConstantsCompatV2.SPEC_TWO_POINT_THREE_VERSION, false, documentUri);
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
