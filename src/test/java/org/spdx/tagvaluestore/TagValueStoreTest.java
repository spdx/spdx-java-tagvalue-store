/**
 * SPDX-FileCopyrightText: Copyright (c) 2020 Source Auditor Inc.
 * SPDX-FileType: SOURCE
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
import java.util.List;
import java.util.stream.Collectors;

import org.spdx.core.DefaultModelStore;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.ModelRegistry;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.Relationship;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxFile;
import org.spdx.library.model.v2.SpdxModelInfoV2_X;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.enumerations.RelationshipType;
import org.spdx.library.model.v3_0_1.SpdxModelInfoV3_0;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.utility.compare.SpdxCompareException;

import junit.framework.TestCase;

/**
 * @author Gary O'Neall
 */
public class TagValueStoreTest extends TestCase {
	
	static final String TAG_VALUE_FILE_PATH = "testResources" + File.separator + "SPDXTagExample-v2.3.spdx";
	private static final String ARTIFACT_OF_FILE_PATH = "testResources" + File.separator + "artifactof.spdx";
	private static final String CASE_FILE_PATH = "testResources" + File.separator + "case.spdx";
	private static final String DASHES_FILE_PATH = "testResources" + File.separator + "dashes.spdx";

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
		ModelRegistry.getModelRegistry().registerModel(new SpdxModelInfoV2_X());
		ModelRegistry.getModelRegistry().registerModel(new SpdxModelInfoV3_0());
		DefaultModelStore.initialize(new InMemSpdxStore(), "https://default.doc", new ModelCopyManager());
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	@SuppressWarnings("unchecked")
	public void testDeSerialize() throws InvalidSPDXAnalysisException, IOException, SpdxCompareException {
		File tagValueFile = new File(TAG_VALUE_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		SpdxDocument deserializedDoc;
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			deserializedDoc = tvs.deSerialize(tagValueInput, false);
		}
		String docUri = null;
		List<SpdxDocument> docs = (List<SpdxDocument>)SpdxModelFactory.getSpdxObjects(tvs, null, 
				SpdxConstantsCompatV2.CLASS_SPDX_DOCUMENT, null, null)
				.collect(Collectors.toList());
		assertEquals(1, docs.size());
		docUri = docs.get(0).getDocumentUri();
		assertEquals(docUri, deserializedDoc.getDocumentUri());
		File testToFile = File.createTempFile("spdx-test", ".spdx");
		try {
			try (OutputStream os = new FileOutputStream(testToFile)) {
				tvs.serialize(os);
			}
			TagValueStore compareStore = new TagValueStore(new InMemSpdxStore());
			String compDocUri = null;
			try (FileInputStream is = new FileInputStream(testToFile)) {
				compareStore.deSerialize(is, false);
			}
			docs = (List<SpdxDocument>)SpdxModelFactory.getSpdxObjects(tvs, null, 
					SpdxConstantsCompatV2.CLASS_SPDX_DOCUMENT, null, null)
					.collect(Collectors.toList());
			assertEquals(1, docs.size());
			compDocUri = docs.get(0).getDocumentUri();
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
		SpdxDocument doc;
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			doc = tvs.deSerialize(tagValueInput, false);
		}
		try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
			tvs.serialize(bas, doc);
			String result = bas.toString();
			assertFalse(result.contains("<text>NOASSERTION</text>"));
			assertTrue(result.contains("PackageCopyrightText: NOASSERTION"));
			assertTrue(result.contains("FileCopyrightText: NOASSERTION"));
			assertTrue(result.contains("SnippetCopyrightText: NOASSERTION"));
		}
	}
	
	public void testArtifactOf() throws InvalidSPDXAnalysisException, IOException {
		File tagValueFile = new File(ARTIFACT_OF_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			tvs.deSerialize(tagValueInput, false);
		}
		String docUri = null;
		@SuppressWarnings("unchecked")
		List<SpdxDocument> docs = (List<SpdxDocument>)SpdxModelFactory.getSpdxObjects(tvs, null, 
				SpdxConstantsCompatV2.CLASS_SPDX_DOCUMENT, null, null)
				.collect(Collectors.toList());
		assertEquals(1, docs.size());
		docUri = docs.get(0).getDocumentUri();
		SpdxFile fileWithArtifactOf = new SpdxFile(tvs, docUri, "SPDXRef-File", null, false);
		Relationship[] relationships = fileWithArtifactOf.getRelationships().toArray(new Relationship[fileWithArtifactOf.getRelationships().size()]);
		assertEquals(1, relationships.length);
		assertEquals(RelationshipType.GENERATED_FROM, relationships[0].getRelationshipType());
		SpdxPackage relatedPackage = (SpdxPackage)(relationships[0].getRelatedSpdxElement().get());
		assertEquals("AcmeTest", relatedPackage.getName().get());
	}
	
	public void testCaseWarning() throws InvalidSPDXAnalysisException, IOException {
		File tagValueFile = new File(CASE_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			tvs.deSerialize(tagValueInput, false);
		}
		assertEquals(1, tvs.getWarnings().size());
	}

	public void testPurposeWithDashes() throws InvalidSPDXAnalysisException, IOException {
		File tagValueFile = new File(DASHES_FILE_PATH);
		TagValueStore tvs = new TagValueStore(new InMemSpdxStore());
		try (InputStream tagValueInput = new FileInputStream(tagValueFile)) {
			tvs.deSerialize(tagValueInput, false);
		}
		assertEquals(0, tvs.getWarnings().size());
	}

}
