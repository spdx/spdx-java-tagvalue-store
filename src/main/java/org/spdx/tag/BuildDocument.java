/**
 * Copyright (c) 2011 Source Auditor Inc.
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
 */
package org.spdx.tag;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxConstants;
import org.spdx.library.model.Annotation;
import org.spdx.library.model.Checksum;
import org.spdx.library.model.ExternalDocumentRef;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.ModelObject;
import org.spdx.library.model.ReferenceType;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxCreatorInformation;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxFile;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxNoAssertionElement;
import org.spdx.library.model.SpdxNoneElement;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.SpdxPackageVerificationCode;
import org.spdx.library.model.SpdxSnippet;
import org.spdx.library.model.enumerations.AnnotationType;
import org.spdx.library.model.enumerations.ChecksumAlgorithm;
import org.spdx.library.model.enumerations.FileType;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.model.license.AnyLicenseInfo;
import org.spdx.library.model.license.ExtractedLicenseInfo;
import org.spdx.library.model.license.InvalidLicenseStringException;
import org.spdx.library.model.license.LicenseInfoFactory;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;


/**
 * Translates an tag-value file to a an SPDX Document.
 *
 * Supports SPDX version 2.0
 *
 * 2.0 changes made by Gary O'Neall
 *
 * @author Rana Rahal, Protecode Inc.
 */
public class BuildDocument implements TagValueBehavior {

	private class AnnotationWithId {
		private Annotation annotation;
		private String id;
		private int lineNumber;
		private AnnotationWithId(String annotator, int lineNumber) throws InvalidSPDXAnalysisException {
			this.annotation =  new Annotation(modelStore, documentNamespace, 
					modelStore.getNextId(IdType.Anonymous, documentNamespace), copyManager, true);
			this.annotation.setAnnotator(annotator);
			this.lineNumber = lineNumber;
		}
		@SuppressWarnings("unused")
		public void setAnnotator(String annotator) throws InvalidSPDXAnalysisException {
			annotation.setAnnotator(annotator);
		}
		public void setDate(String date) throws InvalidSPDXAnalysisException {
			annotation.setAnnotationDate(date);
		}
		public void setAnnotationType(AnnotationType annotationType) throws InvalidSPDXAnalysisException {
			annotation.setAnnotationType(annotationType);
		}
		public void setComment(String comment) throws InvalidSPDXAnalysisException {
			annotation.setComment(comment);
		}
		public void setId(String id) {
			this.id = id;
		}
		public String getId() {
			return this.id;
		}
		public Annotation getAnnotation() {
			return this.annotation;
		}
		public int getLineNumber() {
			return lineNumber;
		}
	}
	private class RelationshipWithId {
		private String id;
		private String relatedId;
		private RelationshipType relationshipType;
		private String comment;
		private int lineNumber;
		public RelationshipWithId(String id, String relatedId,
				RelationshipType relationshipType, int lineNumber) {
			this.id = id;
			this.relatedId = relatedId;
			this.relationshipType = relationshipType;
			this.lineNumber = lineNumber;
		}
		public void setComment(String comment) {
			this.comment = comment;
		}
		public String getId() {
			return id;
		}
		public String getRelatedId() {
			return relatedId;
		}
		public RelationshipType getRelationshipType() {
			return relationshipType;
		}
		public String getComment() {
			return comment;
		}
		public int getLineNumber() {
			return lineNumber;
		}
	}
	
	private class DoapProject {
		
		Relationship relationship;
		SpdxPackage pkg;

		public DoapProject(String projectName, SpdxFile file) throws InvalidSPDXAnalysisException {
			this.pkg = new SpdxPackage(modelStore, documentNamespace, modelStore.getNextId(IdType.SpdxId, documentNamespace), copyManager, true);
			pkg.setName(projectName);
			pkg.setComment("This package was created to replace a deprecated DoapProject");
			relationship = file.createRelationship(file, RelationshipType.GENERATED_FROM, "This relationship was translated from an deprecated ArtifactOf");
			file.getRelationships().add(relationship);
		}

		public List<String> verify() {
			return this.relationship.verify();
		}
		public void setHomePage(String homePage) throws InvalidSPDXAnalysisException {
			this.pkg.setHomepage(homePage);
		}

		public void setProjectUri(String projectUri) throws InvalidSPDXAnalysisException {
			if (!this.pkg.getHomepage().isPresent()) {
				this.pkg.setHomepage(projectUri);
			}
		}
	}

	private static Pattern EXTERNAL_DOC_REF_PATTERN = Pattern.compile("(\\S+)\\s+(\\S+)\\s+SHA1:\\s+(\\S+)");
	private static Pattern RELATIONSHIP_PATTERN = Pattern.compile("(\\S+)\\s+(\\S+)\\s+(\\S+)");
	public static Pattern CHECKSUM_PATTERN = Pattern.compile("([A-Za-z0-9\\-_]+)(:|\\s)\\s*(\\S+)");
	private static Pattern NUMBER_RANGE_PATTERN = Pattern.compile("(\\d+):(\\d+)");
	private static Pattern EXTERNAL_REF_PATTERN = Pattern.compile("([^ ]+) ([^ ]+) (.+)");

	/**
	 * Tags used in the definition of an annotation
	 */
	private Set<String> ANNOTATION_TAGS = new HashSet<>();
	/**
	 * Tags used in the definition of a file
	 */
	private Set<String> FILE_TAGS = new HashSet<>();
	/**
	 * Tags used in the definition of a Snippet
	 */
	private Set<String> SNIPPET_TAGS = new HashSet<>();
	/**
	 * Tags used in the definition of a package
	 */
	/**
	 * Tags used in the definition of an extracted license
	 */
	private Set<String> EXTRACTED_LICENSE_TAGS = new HashSet<>();
	private Set<String> PACKAGE_TAGS = new HashSet<>();
	private Properties constants;
	private SpdxDocument analysis;

	//When we retrieve a list from the SpdxDocument the order changes, therefore keep track of
	//the last object that we are looking at so that we can fill in all of it's information
	private Annotation lastReviewer = null;
	private int lastReviewerLineNumber = 0;

	private ExtractedLicenseInfo lastExtractedLicense = null;
	private int lastExtractedLicenseLineNumber = 0;
	private SpdxFile lastFile = null;
	private List<String> lastFileDependencies = new ArrayList<>();
	private int lastFileLineNumber = 0;
	private SpdxSnippet lastSnippet = null;
	private int lastSnippetLineNumber = 0;
	private DoapProject lastProject = null;
	private int lastProjectLineNumber = 0;
	private Map<String, Integer> elementIdLineNumberMap = new HashMap<>();
	// Keep track of all file dependencies since these need to be added after all of the files
	// have been parsed.  Map of file dependency file name to the SPDX files which depends on it
	private Map<String, List<SpdxFile>> fileDependencyMap = new HashMap<>();
	/**
	 * Map of all snippetFileID's collected during parsing so that we can add the files
	 * at the end of the document creation once the files are actually created
	 */
	private Map<String, List<SpdxSnippet>>  snippetDependencyMap = new HashMap<>();
	private Map<SpdxSnippet, String> snippetByteRangeMap = new HashMap<>();
	private Map<SpdxSnippet, String> snippetLineRangeMap = new HashMap<>();
	/**
	 * Keep track of the last relationship for any following relationship related tags
	 */
	private RelationshipWithId lastRelationship = null;
	/**
	 * Keep track of all relationships and add them at the end of the parsing
	 */
	private List<RelationshipWithId> relationships = new ArrayList<>();
	/**
	 * Keep track of the last annotation for any following annotation related tags
	 */
	private AnnotationWithId lastAnnotation;
	/**
	 * Keep track of all annotations and add them at the end of the parsing
	 */
	private List<AnnotationWithId> annotations = new ArrayList<>();
	
	private String documentNamespace;

	private String specVersion;

	private AnyLicenseInfo dataLicense;

	private String documentName;
	
	private ModelCopyManager copyManager = new ModelCopyManager();	// used for licenses

	List<String> warningMessages;

	/**
	 * True if we have started defining a package in the tag/value file
	 */
	private boolean inPackageDefinition = false;

	/**
	 * True if we have started to define a file AT THE DOCUMENT LEVEL
	 * in the tag/value file.  Note that files defined as part of a package
	 * will have the state flag inPackageDefinition set, and inFileDefinition will be false.
	 */
	private boolean inFileDefinition = false;
	/**
	 * true if we have started to define a Snippet
	 */
	private boolean inSnippetDefinition = false;;
	/**
	 * True if we have started to define an annotation
	 * in the tag/value file.
	 */
	private boolean inAnnotation = false;
	/**
	 * True if we are building an extracted license definition
	 */
	private boolean inExtractedLicenseDefinition = false;

	/**
	 * The last (or current) package being defined by the tag/value file
	 */
	private SpdxPackage lastPackage = null;
	private int lastPackageLineNumber = 0;

	/**
	 * The last external reference found
	 */
	private ExternalRef lastExternalRef = null;
	private IModelStore modelStore;
	private String lastFileId = null;
	private String lastPackageId = null;
	private IModelStore tempModelStore = new InMemSpdxStore();

	public BuildDocument(IModelStore modelStore, Properties constants, List<String> warnings) {
		this.constants = constants;
		this.warningMessages = warnings;
		this.modelStore = modelStore;
		this.ANNOTATION_TAGS.add(constants.getProperty("PROP_ANNOTATION_DATE").trim()+" ");
		this.ANNOTATION_TAGS.add(constants.getProperty("PROP_ANNOTATION_COMMENT").trim()+" ");
		this.ANNOTATION_TAGS.add(constants.getProperty("PROP_ANNOTATION_ID").trim()+" ");
		this.ANNOTATION_TAGS.add(constants.getProperty("PROP_ANNOTATION_TYPE").trim()+" ");

		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_TYPE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_LICENSE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_COPYRIGHT").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_CHECKSUM").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_SEEN_LICENSE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_LIC_COMMENTS").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_COMMENT").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_DEPENDENCY").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_CONTRIBUTOR").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_NOTICE_TEXT").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ELEMENT_ID").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_PROJECT_NAME").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_PROJECT_HOMEPAGE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_PROJECT_URI").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_DOCUMENT_NAMESPACE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_RELATIONSHIP").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_RELATIONSHIP_COMMENT").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ANNOTATOR").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ANNOTATION_DATE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ANNOTATION_COMMENT").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ANNOTATION_ID").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_ANNOTATION_TYPE").trim()+" ");
		this.FILE_TAGS.add(constants.getProperty("PROP_FILE_ATTRIBUTION_TEXT").trim()+" ");

		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_SPDX_ID").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_FROM_FILE_ID").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_BYTE_RANGE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_LINE_RANGE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_CONCLUDED_LICENSE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_LIC_COMMENTS").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_COPYRIGHT").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_COMMENT").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_NAME").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_SNIPPET_SEEN_LICENSE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_DOCUMENT_NAMESPACE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_RELATIONSHIP").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_RELATIONSHIP_COMMENT").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_ANNOTATOR").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_ANNOTATION_DATE").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_ANNOTATION_COMMENT").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_ANNOTATION_ID").trim()+" ");
		this.SNIPPET_TAGS.add(constants.getProperty("PROP_ANNOTATION_TYPE").trim()+" ");

		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_COMMENT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_FILE_NAME").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_CHECKSUM").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_DOWNLOAD_URL").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_SOURCE_INFO").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_DECLARED_LICENSE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_CONCLUDED_LICENSE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_DECLARED_COPYRIGHT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_SHORT_DESC").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_DESCRIPTION").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_VERIFICATION_CODE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_LICENSE_INFO_FROM_FILES").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_LICENSE_COMMENT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_VERSION_INFO").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_ORIGINATOR").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_SUPPLIER").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_HOMEPAGE_URL").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ELEMENT_ID").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_FILE_NAME").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_RELATIONSHIP").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_RELATIONSHIP_COMMENT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ANNOTATOR").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ANNOTATION_DATE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ANNOTATION_COMMENT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ANNOTATION_ID").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_ANNOTATION_TYPE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_EXTERNAL_REFERENCE").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_EXTERNAL_REFERENCE_COMMENT").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_FILES_ANALYZED").trim()+" ");
		this.PACKAGE_TAGS.add(constants.getProperty("PROP_PACKAGE_ATTRIBUTION_TEXT").trim()+" ");

		this.EXTRACTED_LICENSE_TAGS.add(constants.getProperty("PROP_LICENSE_TEXT").trim()+" ");
		this.EXTRACTED_LICENSE_TAGS.add(constants.getProperty("PROP_EXTRACTED_TEXT").trim()+" ");
		this.EXTRACTED_LICENSE_TAGS.add(constants.getProperty("PROP_LICENSE_COMMENT").trim()+" ");
		this.EXTRACTED_LICENSE_TAGS.add(constants.getProperty("PROP_LICENSE_NAME").trim()+" ");
		this.EXTRACTED_LICENSE_TAGS.add(constants.getProperty("PROP_SOURCE_URLS").trim()+" ");
	}

	@Override
	public void enter() throws Exception {
		// do nothing???
	}

	@Override
	public void buildDocument(String tag, String value, int lineNumber) throws Exception {
		tag = tag.trim()+" ";
		value = trim(value.trim());
		if (this.inAnnotation && ANNOTATION_TAGS.contains(tag)) {
			buildAnnotation(tag, value, lastAnnotation);
		} else if (this.inFileDefinition && FILE_TAGS.contains(tag)) {
			buildFile(this.lastFile, tag, value, lineNumber);
		} else if (this.inSnippetDefinition && SNIPPET_TAGS.contains(tag)) {
			buildSnippet(this.lastSnippet, tag, value, lineNumber);
		} else if (this.inPackageDefinition && PACKAGE_TAGS.contains(tag)) {
			buildPackage(this.lastPackage, tag, value, lineNumber);
		} else if (this.inExtractedLicenseDefinition && EXTRACTED_LICENSE_TAGS.contains(tag)) {
			buildExtractedLicense(this.lastExtractedLicense, tag, value, lineNumber);
		} else {
			if (inExtractedLicenseDefinition && lastExtractedLicense != null) {
				verifyElement(lastExtractedLicense.verify(), "Extracted License", lastExtractedLicenseLineNumber, false);
			}
			if (inFileDefinition) {
				addLastFile();
			}
			if (inSnippetDefinition) {
				addLastSnippet();
			}
			inAnnotation = false;
			inFileDefinition = false;
			inPackageDefinition = false;
			inSnippetDefinition = false;
			buildDocumentProperties(tag, value, lineNumber);
		}
	}

	/**
	 * Add tag value properties to an existing snippet
	 * @param snippet
	 * @param tag
	 * @param value
	 * @param lineNumber
	 * @throws InvalidSpdxTagFileException
	 * @throws InvalidSPDXAnalysisException
	 * @throws InvalidLicenseStringException
	 */
	private void buildSnippet(SpdxSnippet snippet, String tag, String value, int lineNumber) throws InvalidSpdxTagFileException, InvalidSPDXAnalysisException, InvalidLicenseStringException {
		if (snippet == null) {
			throw(new InvalidSpdxTagFileException("Missing Snippet ID - An SPDX Snippet ID must be specified before the snippet properties"));
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_FROM_FILE_ID"))) {
			// Since the files have not all been parsed, we just keep track of the
			// dependencies in a hashmap until we finish all processing and are building the package
			List<SpdxSnippet> snippetsWithThisAsADependency = this.snippetDependencyMap.get(value);
			if (snippetsWithThisAsADependency == null) {
				snippetsWithThisAsADependency = new ArrayList<>();
				this.snippetDependencyMap.put(value, snippetsWithThisAsADependency);
			}
			snippetsWithThisAsADependency.add(snippet);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_BYTE_RANGE"))) {
			snippetByteRangeMap.put(snippet, value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_LINE_RANGE"))) {
			snippetLineRangeMap.put(snippet, value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_CONCLUDED_LICENSE"))) {
			snippet.setLicenseConcluded(LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager));
			// can not verify any licenses at this point since the extracted license infos may not be set
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_LIC_COMMENTS"))) {
			snippet.setLicenseComments(value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_COPYRIGHT"))) {
			snippet.setCopyrightText(value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_COMMENT"))) {
			snippet.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_NAME"))) {
			snippet.setName(value);
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_SEEN_LICENSE"))) {
			snippet.getLicenseInfoFromFiles().add(LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager));
			// can not verify any licenses at this point since the extracted license infos may not be set
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATOR"))) {
			if (lastAnnotation != null) {
				annotations.add(lastAnnotation);
			}
			this.inAnnotation = true;
			lastAnnotation = new AnnotationWithId(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP"))) {
			if (lastRelationship != null) {
				relationships.add(lastRelationship);
			}
			lastRelationship = parseRelationship(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP_COMMENT"))) {
			if (lastRelationship == null) {
				throw(new InvalidSpdxTagFileException("Relationship comment found outside of a relationship: "+value + " at line number "+lineNumber));
			}
			lastRelationship.setComment(value);
		} else {
			throw new InvalidSPDXAnalysisException("Error parsing snippet.  Unrecognized tag: "+tag + " at line number " + lineNumber);
		}
	}

	private void verifyElement(List<String> verify, String prefix, int lineNumber) {
		verifyElement(verify, prefix, lineNumber, false);
	}

	/**
	 * Add warning messages for any element verification list
	 * @param verify List of verification warnings
	 * @param prefix Prefix to prepend the warning with
	 * @param lineNumber Line number where the error occurs
	 * @param ignoreMissingLicenseText if true, don't record any missing license text errors
	 */
	private void verifyElement(List<String> verify, String prefix, int lineNumber, boolean ignoreMissingLicenseText) {
		if (!verify.isEmpty()) {
			for (String verMsg:verify) {
				if (!ignoreMissingLicenseText || !verMsg.contains("Missing required license text")) {
					boolean found = false;
					String newWarning = prefix + " at line "+lineNumber+" invalid: "+verMsg;
					for (String existingWarn:this.warningMessages) {
						if (existingWarn.equals(newWarning)) {
							found = true;
							break;
						}
					}
					if (!found) {
						this.warningMessages.add(newWarning);
					}
				}
			}
		}
	}


	/**
	 * @param license
	 * @param tag
	 * @param value
	 * @param lineNumber
	 * @throws InvalidSPDXAnalysisException 
	 */
	private void buildExtractedLicense(
			ExtractedLicenseInfo license, String tag, String value, int lineNumber) throws InvalidSPDXAnalysisException {
		if (tag.equals(constants.getProperty("PROP_EXTRACTED_TEXT"))) {
			if (lastExtractedLicense == null) {
				throw(new InvalidSpdxTagFileException("Missing Extracted License - An  extracted license ID must be provided before the license text at line number "+lineNumber));
			}
			license.setExtractedText(value);
		} else if (tag.equals(constants.getProperty("PROP_LICENSE_NAME"))) {
			if (lastExtractedLicense == null) {
				throw(new InvalidSpdxTagFileException("Missing Extracted License - An  extracted license ID must be provided before the license name at line number "+lineNumber));
			}
			license.setName(value);
		} else if (tag.equals(constants.getProperty("PROP_SOURCE_URLS"))) {
			if (lastExtractedLicense == null) {
				throw(new InvalidSpdxTagFileException("Missing Extracted License - An  extracted license ID must be provided before the license URL at line number "+lineNumber));
			}
			String[] values = value.split(",");
			for (int i = 0; i < values.length; i++) {
				license.getSeeAlso().add(values[i].trim());
			}
		} else if (tag.equals(constants.getProperty("PROP_LICENSE_COMMENT"))) {
			if (lastExtractedLicense == null) {
				throw(new InvalidSpdxTagFileException("Missing Extracted License - An  extracted license ID must be provided before the license comment at line number "+lineNumber));
			}
			license.setComment(value);
		}
	}

	private void buildDocumentProperties(String tag, String value, int lineNumber) throws Exception {
		if (tag.equals(constants.getProperty("PROP_SPDX_VERSION"))) {
			this.specVersion = value;
			if (analysis != null) {
				analysis.setSpecVersion(value);
			}
		} else if (tag.equals(constants.getProperty("PROP_SPDX_DATA_LICENSE"))) {
			try {
				this.dataLicense = LicenseInfoFactory.getListedLicenseById(value);
			} catch(InvalidSPDXAnalysisException ex) {
				this.dataLicense = null;
			}
			if (this.dataLicense == null) {
				this.dataLicense = new ExtractedLicenseInfo(value, "NO TEXT FOR "+value);
			}
			if (analysis != null) {
				analysis.setDataLicense(this.dataLicense);
			}
		} else if (tag.equals(constants.getProperty("PROP_DOCUMENT_NAME"))) {
			this.documentName = value;
			if (analysis != null) {
				this.analysis.setName(value);
			}
		} else if (tag.equals(constants.getProperty("PROP_DOCUMENT_NAMESPACE"))) {
			if (this.analysis != null) {
				throw(new InvalidSpdxTagFileException("More than one document namespace was specified at line number "+lineNumber));
			}
			this.documentNamespace = value;
			this.analysis = new SpdxDocument(modelStore, documentNamespace, copyManager, true);
			if (this.specVersion != null) {
				this.analysis.setSpecVersion(this.specVersion);
			}
			if (this.dataLicense != null) {
				this.analysis.setDataLicense(this.dataLicense);
			}
			if (this.documentName != null) {
				this.analysis.setName(this.documentName);
			}
		} else if (tag.equals(constants.getProperty("PROP_ELEMENT_ID"))) {
			if (!value.equals(SpdxConstants.SPDX_DOCUMENT_ID)) {
				throw(new InvalidSpdxTagFileException("SPDX Document "+value
						+" is invalid.  Document IDs must be "+SpdxConstants.SPDX_DOCUMENT_ID + " at line number "+lineNumber));
			}
		} else if (tag.equals(constants.getProperty("PROP_EXTERNAL_DOC_URI"))) {
			checkAnalysisNull();
			addExternalDocRef(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP"))) {
			if (lastRelationship != null) {
				relationships.add(lastRelationship);
			}
			lastRelationship = parseRelationship(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP_COMMENT"))) {
			if (lastRelationship == null) {
				throw(new InvalidSpdxTagFileException("Relationship comment found outside of a relationship: "+value + " at line number "+lineNumber));
			}
			lastRelationship.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATOR"))) {
			if (lastAnnotation != null) {
				annotations.add(lastAnnotation);
			}
			this.inAnnotation = true;
			lastAnnotation = new AnnotationWithId(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_DATE"))) {
			throw(new InvalidSpdxTagFileException("Annotation date found outside of an annotation: "+value + " at line number "+lineNumber));
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_COMMENT"))) {
			throw(new InvalidSpdxTagFileException("Annotation comment found outside of an annotation: "+value + " at line number "+lineNumber));
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_ID"))) {
			throw(new InvalidSpdxTagFileException("Annotation ID found outside of an annotation: "+value + " at line number "+lineNumber));
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_TYPE"))) {
			throw(new InvalidSpdxTagFileException("Annotation type found outside of an annotation: "+value + " at line number "+lineNumber));
		} else if (tag.equals(constants.getProperty("PROP_CREATION_CREATOR"))) {
			checkAnalysisNull();
			if (analysis.getCreationInfo() == null) {				
				SpdxCreatorInformation creator = new SpdxCreatorInformation(modelStore, documentNamespace, modelStore.getNextId(IdType.Anonymous,  documentNamespace), copyManager, true);
				analysis.setCreationInfo(creator);
			}
			analysis.getCreationInfo().getCreators().add(value);
		} else if (tag.equals(constants.getProperty("PROP_CREATION_CREATED"))) {
			checkAnalysisNull();
			if (analysis.getCreationInfo() == null) {				
				SpdxCreatorInformation creator = new SpdxCreatorInformation(modelStore, documentNamespace, modelStore.getNextId(IdType.Anonymous,  documentNamespace), copyManager, true);
				analysis.setCreationInfo(creator);
			}
			analysis.getCreationInfo().setCreated(value);
		} else if (tag.equals(constants.getProperty("PROP_CREATION_COMMENT"))) {
			checkAnalysisNull();
			if (analysis.getCreationInfo() == null) {				
				SpdxCreatorInformation creator = new SpdxCreatorInformation(modelStore, documentNamespace, modelStore.getNextId(IdType.Anonymous,  documentNamespace), copyManager, true);
				analysis.setCreationInfo(creator);
			}
			analysis.getCreationInfo().setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_LICENSE_LIST_VERSION"))) {
			checkAnalysisNull();
			if (analysis.getCreationInfo() == null) {				
				SpdxCreatorInformation creator = new SpdxCreatorInformation(modelStore, documentNamespace, modelStore.getNextId(IdType.Anonymous,  documentNamespace), copyManager, true);
				analysis.setCreationInfo(creator);
			}
			analysis.getCreationInfo().setLicenseListVersion(value);
		} else if (tag.equals(constants.getProperty("PROP_SPDX_COMMENT"))) {
			checkAnalysisNull();
			analysis.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_REVIEW_REVIEWER"))) {
			checkAnalysisNull();
			lastReviewer = new Annotation(modelStore, documentNamespace, modelStore.getNextId(IdType.Anonymous,  documentNamespace), copyManager, true);
			lastReviewer.setAnnotationType(AnnotationType.REVIEW);
			lastReviewer.setAnnotator(value);
			analysis.getAnnotations().add(lastReviewer);
			warningMessages.add("Converted deprecated Reviewer to annotation for reviewer "+value);
			lastReviewerLineNumber = lineNumber;
			this.verifyElement(lastReviewer.verify(), "Reviewer", lastReviewerLineNumber);
		} else if (tag.equals(constants.getProperty("PROP_REVIEW_DATE"))) {
			checkAnalysisNull();
			if (lastReviewer == null) {
				throw(new InvalidSpdxTagFileException("Missing Reviewer - A reviewer must be provided before a review date"));
			}
			lastReviewer.setAnnotationDate(value);
			this.verifyElement(lastReviewer.verify(), "Reviewer", lastReviewerLineNumber);
		} else if (tag.equals(constants.getProperty("PROP_REVIEW_COMMENT"))) {
			checkAnalysisNull();
			if (lastReviewer == null) {
				throw(new InvalidSpdxTagFileException("Missing Reviewer - A reviewer must be provided before a review comment"));
			}
			lastReviewer.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_LICENSE_ID"))) {
			checkAnalysisNull();
			if (inExtractedLicenseDefinition) {
				verifyElement(lastExtractedLicense.verify(), "Extracted License", lastExtractedLicenseLineNumber, false);
			}
			if (modelStore.exists(documentNamespace, value)) {
				lastExtractedLicense = new ExtractedLicenseInfo(modelStore, documentNamespace, value, copyManager, false);
			} else {
				lastExtractedLicense = new ExtractedLicenseInfo(modelStore, documentNamespace, value, copyManager, true);
				lastExtractedLicense.setExtractedText("WARNING: TEXT IS REQUIRED");  //change text later
				lastExtractedLicenseLineNumber = lineNumber;
			}
			analysis.addExtractedLicenseInfos(lastExtractedLicense);
			this.inExtractedLicenseDefinition = true;
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_DECLARED_NAME"))) {
			checkAnalysisNull();
			inPackageDefinition = true;
			inFileDefinition = false;
			inAnnotation = false;
			inSnippetDefinition = false;
			inExtractedLicenseDefinition = false;
			addLastPackage();
			this.lastPackage = new SpdxPackage(tempModelStore, documentNamespace, tempModelStore.getNextId(IdType.Anonymous,  documentNamespace), // We create this as anonymous and copy to the real package with the correct ID later 
					copyManager, true);
			this.lastPackage.setName(value);
			lastPackageLineNumber = lineNumber;
		} else if (tag.equals(constants.getProperty("PROP_FILE_NAME"))) {
			checkAnalysisNull();
			//NOTE: This must follow the inPackageDefinition check since
			// if a file is defined following a package, it is assumed to
			// be part of the package and not something standalone
			addLastFile();
			inFileDefinition = true;
			inPackageDefinition = false;
			inAnnotation = false;
			inSnippetDefinition = false;
			inExtractedLicenseDefinition = false;
			
			this.lastFile = new SpdxFile(tempModelStore, documentNamespace, tempModelStore.getNextId(IdType.Anonymous, documentNamespace), // We create this as anonymous and copy to the real package with the correct ID later 
					copyManager, true);
			this.lastFile.setName(value);
			lastFileLineNumber = lineNumber;
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_SPDX_ID"))) {
			checkAnalysisNull();
			addLastSnippet();
			inSnippetDefinition = true;
			inFileDefinition = false;
			inPackageDefinition = false;
			inAnnotation = false;
			inExtractedLicenseDefinition = false;
			this.lastSnippet = new SpdxSnippet(modelStore, documentNamespace, value, copyManager, true);
			this.lastSnippetLineNumber = lineNumber;
		} else {
			throw new InvalidSpdxTagFileException("Expecting a definition of a file, package, license information, or document property at "+tag+value+" line number "+lineNumber);
		}
	}


	private void addLastPackage() throws InvalidSPDXAnalysisException {
		if (this.lastPackage != null) {
			// A bit klunky, but we need to create a new package and copy all the elements since
			// we don't know the SPDX ID until after the lastPackage is created
			if (Objects.isNull(lastPackageId)) {
				throw new InvalidSpdxTagFileException("Missing SPDX ID for package defined at "+lastPackageLineNumber);
			}
			SpdxPackage newPkg = new SpdxPackage(modelStore, documentNamespace, lastPackageId, copyManager, true);
			newPkg.copyFrom(lastPackage);
			elementIdLineNumberMap.put(lastPackageId, lastPackageLineNumber);
			lastPackageId = null;
			this.lastPackage = null;
		}
	}

	/**
	 * Adds the last file to either the last package or the document
	 * @throws InvalidSPDXAnalysisException
	 *
	 */
	private void addLastFile() throws InvalidSPDXAnalysisException {
		if (this.lastFile != null) {
			if (Objects.isNull(lastFileId)) {
				throw new InvalidSPDXAnalysisException("Missing SPDX ID for file defined at line "+this.lastFileLineNumber);
			}
			SpdxFile newFile = new SpdxFile(modelStore, documentNamespace, lastFileId, copyManager, true);
			newFile.copyFrom(this.lastFile);
			for (String depdendeFileName:lastFileDependencies) {
				addFileDependency(newFile, depdendeFileName);
			}
			
			lastFileDependencies.clear();
			lastFileId = null;
			if (lastPackage != null) {
				this.lastPackage.addFile(newFile);
			}
			elementIdLineNumberMap.put(lastFileId,lastFileLineNumber);
			lastFileId = null;
		}
		this.lastFile = null;
	}

	/**
	 * Adds the last snippet to the document
	 * @throws InvalidSPDXAnalysisException
	 *
	 */
	private void addLastSnippet() throws InvalidSPDXAnalysisException {
		if (this.lastSnippet != null) {
			elementIdLineNumberMap.put(lastSnippet.getId(), lastSnippetLineNumber);
		}
		this.lastSnippet = null;
	}

	/**
	 * @param tag
	 * @param value
	 * @param annotation
	 * @throws InvalidSPDXAnalysisException
	 */
	private void buildAnnotation(String tag, String value,
			AnnotationWithId annotation) throws InvalidSPDXAnalysisException {
		if (tag.equals(constants.getProperty("PROP_ANNOTATION_DATE"))) {
			annotation.setDate(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_COMMENT"))) {
			annotation.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_ID"))) {
			annotation.setId(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATION_TYPE"))) {
			try {
				AnnotationType annotationType = AnnotationType.valueOf(value);
				annotation.setAnnotationType(annotationType);
			} catch (IllegalArgumentException ex) {
				throw(new InvalidSPDXAnalysisException("Invalid annotation type: "+value + " at line number "+annotation.getLineNumber()));
			}
		}
	}

	/**
	 * @param value
	 * @return
	 * @throws InvalidSpdxTagFileException
	 */
	private RelationshipWithId parseRelationship(String value, int lineNumber) throws InvalidSpdxTagFileException {
		Matcher matcher = RELATIONSHIP_PATTERN.matcher(value.trim());
		if (!matcher.find()) {
			throw(new InvalidSpdxTagFileException("Invalid relationship: "+value + " at line number "+lineNumber));
		}
		RelationshipType relationshipType = null;
		try {
			relationshipType = RelationshipType.valueOf(matcher.group(2).toUpperCase());
		} catch (IllegalArgumentException ex) {
			throw(new InvalidSpdxTagFileException("Invalid relationship type: "+value + " at line number "+lineNumber));
		}
		return new RelationshipWithId(matcher.group(1), matcher.group(3),
				relationshipType, lineNumber);
	}

	private void checkAnalysisNull() throws InvalidSpdxTagFileException, InvalidSPDXAnalysisException,InvalidFileFormatException {
		if (this.analysis == null) {
			if (this.specVersion != null && this.specVersion.compareTo("SPDX-2.0") < 0) {
				this.analysis = new SpdxDocument(modelStore, generateDocumentNamespace(), copyManager, true);
			} else {
				throw(new InvalidFileFormatException("The SPDX Document Namespace must be set before other SPDX document properties are set."));
			}
		}
	}

	/**
	 * @return Generated document namespace
	 */
	private String generateDocumentNamespace() {
		return "http://spdx.org/documents/"+UUID.randomUUID().toString();
	}

	/**
	 * @param value
	 * @param lineNumber
	 * @throws InvalidSpdxTagFileException
	 * @throws InvalidSPDXAnalysisException
	 */
	private void addExternalDocRef(String value, int lineNumber) throws InvalidSpdxTagFileException, InvalidSPDXAnalysisException {
		ExternalDocumentRef ref = parseExternalDocumentRef(value, lineNumber, analysis);
		verifyElement(ref.verify(), "External Document Reference", lineNumber);
		this.analysis.getExternalDocumentRefs().add(ref);
	}

	/**
	 * Parse a tag/value external document reference string
	 * @param refStr String containing a tag/value representation of the external document ref
	 * @param lineNumber
	 * @param document SPDX document where the external document reference will be store
	 * @return ExternalDocumentRef represented by the pattern
	 * @throws InvalidSPDXAnalysisException 
	 */
	public static ExternalDocumentRef parseExternalDocumentRef(String refStr, int lineNumber, SpdxDocument document) throws InvalidSPDXAnalysisException {
		Matcher matcher = EXTERNAL_DOC_REF_PATTERN.matcher(refStr.trim());
		if (!matcher.find()) {
			throw(new InvalidSpdxTagFileException("Invalid external document reference: "+refStr+" at line number "+lineNumber));
		}
		Checksum checksum = document.createChecksum(ChecksumAlgorithm.SHA1, matcher.group(3));
		ExternalDocumentRef ref = document.createExternalDocumentRef(matcher.group(1), matcher.group(2), checksum);
		return ref;
	}

	/**
	 * @param pkg
	 * @param tag
	 * @param value
	 * @param lineNumber
	 * @throws InvalidSPDXAnalysisException
	 * @throws InvalidSpdxTagFileException
	 * @throws InvalidLicenseStringException
	 */
	private void buildPackage(SpdxPackage pkg, String tag, String value, int lineNumber)
			throws InvalidSPDXAnalysisException, InvalidSpdxTagFileException, InvalidLicenseStringException {
		if (tag.equals(constants.getProperty("PROP_ELEMENT_ID"))) {
			if (lastPackageId != null) {
				throw new InvalidSpdxTagFileException("SPDX ID "+lastPackageId+" was not consumed before new SPDX ID "+value+" was used for a package");
			}
			lastPackageId = value;
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_VERSION_INFO"))) {
			pkg.setVersionInfo(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_FILE_NAME"))) {
			pkg.setPackageFileName(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_SUPPLIER"))) {
			pkg.setSupplier(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_ORIGINATOR"))) {
			pkg.setOriginator(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_DOWNLOAD_URL"))) {
			pkg.setDownloadLocation(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_VERIFICATION_CODE"))) {
			SpdxPackageVerificationCode verificationCode = null;
			if (value.contains("(")) {
				String[] verification = value.split("\\(");
				String[] excludedFiles = verification[1].replace(")", "").replace("excludes:", "").split(",");
				List<String> excludedFilesList = new ArrayList<>();
				for (int i = 0; i < excludedFiles.length; i++) {
					
					excludedFilesList.add(excludedFiles[i].trim());
				}
				verificationCode = pkg.createPackageVerificationCode(verification[0].trim(), excludedFilesList);
			}
			else {
				verificationCode = pkg.createPackageVerificationCode(value, new ArrayList<String>());
			}
			verifyElement(verificationCode.verify(), "Verification Code", lineNumber);
			pkg.setPackageVerificationCode(verificationCode);
		} else if (constants.getProperty("PROP_PACKAGE_CHECKSUM").startsWith(tag)) {
			Checksum checksum = parseChecksum(value, lineNumber, analysis);
			verifyElement(checksum.verify(), "Package Checksum", lineNumber);
			pkg.addChecksum(checksum);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_HOMEPAGE_URL"))) {
			pkg.setHomepage(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_SOURCE_INFO"))) {
			pkg.setSourceInfo(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_CONCLUDED_LICENSE"))) {
			AnyLicenseInfo licenseSet = LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager);
			// can not verify any licenses at this point since the extracted license infos may not be set
			pkg.setLicenseConcluded(licenseSet);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_LICENSE_INFO_FROM_FILES"))) {
			AnyLicenseInfo license = LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager);
			// can not verify any licenses at this point since the extracted license infos may not be set
			pkg.getLicenseInfoFromFiles().add(license);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_DECLARED_LICENSE"))) {
			AnyLicenseInfo licenseSet = LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager);
			// can not verify any licenses at this point since the extracted license infos may not be set
			pkg.setLicenseDeclared(licenseSet);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_LICENSE_COMMENT"))) {
			pkg.setLicenseComments(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_DECLARED_COPYRIGHT"))) {
			pkg.setCopyrightText(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_SHORT_DESC"))) {
			pkg.setSummary(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_DESCRIPTION"))) {
			pkg.setDescription(value);
		} else if (tag.equals(constants.getProperty("PROP_EXTERNAL_REFERENCE"))) {
			this.lastExternalRef = parseExternalRef(value, lineNumber);
			verifyElement(this.lastExternalRef.verify(), "External Reference", lineNumber);
			pkg.addExternalRef(this.lastExternalRef);
		} else if (tag.equals(constants.getProperty("PROP_EXTERNAL_REFERENCE_COMMENT"))) {
			if (this.lastExternalRef == null) {
				throw new InvalidSpdxTagFileException("External reference comment found without an external reference: "+value + " at line number "+lineNumber);
			}
			if (this.lastExternalRef.getComment().isPresent() && !this.lastExternalRef.getComment().get().isEmpty()) {
				throw new InvalidSpdxTagFileException("Second reference comment found for the same external reference: "+value + " at line number "+lineNumber);
			}
			this.lastExternalRef.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATOR"))) {
			if (lastAnnotation != null) {
				annotations.add(lastAnnotation);
			}
			this.inAnnotation = true;
			lastAnnotation = new AnnotationWithId(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP"))) {
			if (lastRelationship != null) {
				relationships.add(lastRelationship);
			}
			lastRelationship = parseRelationship(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP_COMMENT"))) {
			if (lastRelationship == null) {
				throw(new InvalidSpdxTagFileException("Relationship comment found outside of a relationship: "+value + " at line number "+lineNumber));
			}
			lastRelationship.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_NAME"))) {
			addLastFile();
			this.lastFile = new SpdxFile(tempModelStore, documentNamespace, tempModelStore.getNextId(IdType.Anonymous, documentNamespace), // We create this as anonymous and copy to the real package with the correct ID later 
					copyManager, true);
			this.lastFile.setName(value);
			this.inFileDefinition = true;
			inSnippetDefinition = false;
			inAnnotation = false;
		} else if (tag.equals(constants.getProperty("PROP_SNIPPET_SPDX_ID"))) {
			addLastSnippet();
			inSnippetDefinition = true;
			inFileDefinition = false;
			inPackageDefinition = false;
			inAnnotation = false;
			this.lastSnippet = new SpdxSnippet(modelStore, documentNamespace, value, copyManager, true);
			elementIdLineNumberMap.put(value, lineNumber);
			this.lastSnippetLineNumber = lineNumber;
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_COMMENT"))) {
			pkg.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_ATTRIBUTION_TEXT"))) {
			pkg.getAttributionText().add(value);
		} else if (tag.equals(constants.getProperty("PROP_PACKAGE_FILES_ANALYZED"))) {
			if ("TRUE".equals(value.toUpperCase())) {
				pkg.setFilesAnalyzed(true);
			} else if ("FALSE".equals(value.toUpperCase())) {
				pkg.setFilesAnalyzed(false);
			} else {
				throw(new InvalidSpdxTagFileException("Invalid value for files analyzed.  Must be 'true' or 'false'.  Found value: "+value+" at line number "+lineNumber));
			}
		} else {
			throw(new InvalidSpdxTagFileException("Expecting a file definition, snippet definition or a package property.  Found "+value+" at line number "+lineNumber));
		}
	}

	/**
	 * Parse the external reference string
	 * @param value
	 * @param lineNumber
	 * @return
	 * @throws InvalidSpdxTagFileException
	 * @throws InvalidSPDXAnalysisException
	 */
	private ExternalRef parseExternalRef(String value, int lineNumber) throws InvalidSpdxTagFileException, InvalidSPDXAnalysisException {
		Matcher matcher = EXTERNAL_REF_PATTERN.matcher(value);
		if (!matcher.find()) {
			throw new InvalidSpdxTagFileException("Invalid External Ref format: "+value+" at line number "+lineNumber);
		}
		ReferenceCategory referenceCategory = null;
		try {
			referenceCategory = ReferenceCategory.valueOf(matcher.group(1).trim().replace("-", "_"));
		} catch(IllegalArgumentException ex) {
			throw new InvalidSpdxTagFileException("Invalid External Ref category: "+value+" at line number "+lineNumber);
		}
		ReferenceType referenceType = null;
		String tagType = matcher.group(2).trim();
		try {
			// First, try to find a listed type
			referenceType = ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName(tagType);
		} catch (InvalidSPDXAnalysisException e) {
			referenceType = null;
		}
		if (referenceType == null) {
			try {
				URI refTypeUri = null;
				if (tagType.contains("/") || tagType.contains(":")) {
					// Assume a full URI
					refTypeUri = new URI(tagType);
				} else {
					// User the document namespace
					refTypeUri = new URI(documentNamespace + "#" + matcher.group(2).trim());
				}
				referenceType = new ReferenceType(refTypeUri.toString());
			} catch (URISyntaxException e) {
				throw new InvalidSpdxTagFileException("Invalid External Ref type: "+value+" at line number "+lineNumber);
			}
		}
		return analysis.createExternalRef(referenceCategory, referenceType, matcher.group(3), null);
	}

	/**
	 * Creates a Checksum from the parameters specified in the tag value
	 * @param value checksum value in tag/value format
	 * @param lineNumber
	 * @param document SPDX document containing the checksum
	 * @return
	 * @throws InvalidSPDXAnalysisException 
	 */
	public static Checksum parseChecksum(String value, int lineNumber, SpdxDocument document) throws InvalidSPDXAnalysisException {
		Matcher matcher = CHECKSUM_PATTERN.matcher(value.trim());
		if (!matcher.find()) {
			throw(new InvalidSpdxTagFileException("Invalid checksum: "+value+" at line number "+lineNumber));
		}
		try {
			ChecksumAlgorithm algorithm = ChecksumAlgorithm.valueOf(matcher.group(1));
			return document.createChecksum(algorithm, matcher.group(3));
		} catch(IllegalArgumentException ex) {
			throw(new InvalidSpdxTagFileException("Invalid checksum algorithm: "+value+" at line number "+lineNumber));
		}
	}

	/**
	 * @param file
	 * @param tag
	 * @param value
	 * @param lineNumber
	 */
	private void buildFile(SpdxFile file, String tag, String value, int lineNumber)
			throws Exception {
		if (file == null) {
			if (FILE_TAGS.contains(tag)) {
				throw(new InvalidSpdxTagFileException("Missing File Name - A file name must be specified before the file properties at line number "+lineNumber));
			} else {
				throw(new InvalidSpdxTagFileException("Unrecognized SPDX Tag: "+tag+" at line number "+lineNumber));
			}
		}
		if (tag.equals(constants.getProperty("PROP_ELEMENT_ID"))) {
			if (Objects.nonNull(lastFileId)) {
				throw new InvalidSpdxTagFileException("Multiple SPDX ID's defined for file at line "+lineNumber+"; old ID="+lastFileId);
			}
			lastFileId = value;
		} else if (tag.equals(constants.getProperty("PROP_FILE_TYPE"))) {
			FileType fileType = null;
			try {
				fileType = FileType.valueOf(value.trim());
			} catch(IllegalArgumentException ex) {
				try {
					fileType = FileType.valueOf(value.trim().toUpperCase());
					this.warningMessages.add("Invalid filetype - needs to be uppercased: "+value+" at line number "+lineNumber);
				} catch(IllegalArgumentException ex2) {
					throw(new InvalidSpdxTagFileException("Unknown file type: "+value+" at line number "+lineNumber));
				}
			}
			file.addFileType(fileType);
		} else if (constants.getProperty("PROP_FILE_CHECKSUM").startsWith(tag)) {
			file.addChecksum(parseChecksum(value, lineNumber, analysis));
		} else if (tag.equals(constants.getProperty("PROP_FILE_LICENSE"))) {
			AnyLicenseInfo licenseSet = LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager);
			// can not verify any licenses at this point since the extracted license infos may not be set
			file.setLicenseConcluded(licenseSet);
		} else if (tag.equals(constants.getProperty("PROP_FILE_SEEN_LICENSE"))) {
			AnyLicenseInfo fileLicense = LicenseInfoFactory.parseSPDXLicenseString(value, modelStore, documentNamespace, copyManager);
			// can not verify any licenses at this point since the extracted license infos may not be set
			file.getLicenseInfoFromFiles().add(fileLicense);
		} else if (tag.equals(constants.getProperty("PROP_FILE_LIC_COMMENTS"))) {
			file.setLicenseComments(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_COPYRIGHT"))) {
			file.setCopyrightText(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_COMMENT"))) {
			file.setComment(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_NOTICE_TEXT"))) {
			file.setNoticeText(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_CONTRIBUTOR"))) {
			file.getFileContributors().add(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_DEPENDENCY"))) {
			this.lastFileDependencies.add(value);
		} else if (tag.equals(constants.getProperty("PROP_FILE_ATTRIBUTION_TEXT"))) {
			file.getAttributionText().add(value);
		} else if (tag.equals(constants.getProperty("PROP_ANNOTATOR"))) {
			if (lastAnnotation != null) {
				annotations.add(lastAnnotation);
			}
			this.inAnnotation = true;
			lastAnnotation = new AnnotationWithId(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP"))) {
			if (lastRelationship != null) {
				relationships.add(lastRelationship);
			}
			lastRelationship = parseRelationship(value, lineNumber);
		} else if (tag.equals(constants.getProperty("PROP_RELATIONSHIP_COMMENT"))) {
			if (lastRelationship == null) {
				throw(new InvalidSpdxTagFileException("Relationship comment found outside of a relationship: "+value+" at line number "+lineNumber));
			}
			lastRelationship.setComment(value);
		} else {
			buildProject(file, tag, value, lineNumber);
		}
	}

	/**
	 * Adds a file dependency to a file
	 * @param file
	 * @param dependentFileName
	 */
	private void addFileDependency(SpdxFile file, String dependentFileName) {
		// Since the files have not all been parsed, we just keep track of the
		// dependencies in a hashmap until we finish all processing and are building the package
		List<SpdxFile> filesWithThisAsADependency = this.fileDependencyMap.get(dependentFileName);
		if (filesWithThisAsADependency == null) {
			filesWithThisAsADependency = new ArrayList<>();
			this.fileDependencyMap.put(dependentFileName, filesWithThisAsADependency);
		}
		filesWithThisAsADependency.add(file);
	}

	/**
	 * @param file
	 * @param tag
	 * @param value
	 * @param lineNumber
	 */
	private void buildProject(SpdxFile file, String tag, String value, int lineNumber)
			throws Exception {
		if (tag.equals(constants.getProperty("PROP_PROJECT_NAME"))) {
			if (lastProject != null) {
				verifyElement(lastProject.verify(), "DOAP Project", lastProjectLineNumber);
			}
			lastProject = new DoapProject(value, file);
			lastProjectLineNumber = lineNumber;
		} else {
			if (tag.equals(constants.getProperty("PROP_PROJECT_HOMEPAGE"))) {
				if (lastProject == null) {
					throw(new InvalidSpdxTagFileException("Missing Project Name - A project name must be provided before the project properties at line number" + lineNumber));
				}
				lastProject.setHomePage(value);
			} else if (tag.equals(constants.getProperty("PROP_PROJECT_URI"))) {
				lastProject.setProjectUri(value);
			} else {
				throw(new InvalidSpdxTagFileException("Unrecognized tag: "+tag+" at line number" + lineNumber));
			}
		}
	}

	private static String trim(String value) {
		value = value.replaceAll("\u00A0", " ");
		value = value.trim();
		value = value.replaceAll("<text>", "").replaceAll("</text>", "");
		return value;
	}

	@Override
	public void exit() throws Exception {
		if (inExtractedLicenseDefinition && lastExtractedLicense != null) {
			verifyElement(lastExtractedLicense.verify(), "Extracted License", lastExtractedLicenseLineNumber, false);
		}
		addLastFile();
		addLastPackage();
		if (this.lastPackage != null) {
			elementIdLineNumberMap.put(this.lastPackage.getId(), this.lastPackageLineNumber);
		}
		fixFileAndSnippetDependencies();
		addRelationships();
		checkSinglePackageDefault();
		addAnnotations();
		modelStore.getAllItems(documentNamespace, SpdxConstants.CLASS_SPDX_PACKAGE).forEach(element -> {
			if (modelStore.getIdType(element.getId()).equals(IdType.Anonymous)) {
				this.warningMessages.add("Anonomous type was found for package");
			}
			if (elementIdLineNumberMap.containsKey(element.getId())) {
				try {
					verifyElement(new SpdxPackage(modelStore, documentNamespace, element.getId(), copyManager, false).verify(), "Package", elementIdLineNumberMap.get(element.getId()));
				} catch (InvalidSPDXAnalysisException e) {
					this.warningMessages.add("Exception verifying element "+element.getId()+": "+e.getMessage());
				}
			}
		});
		modelStore.getAllItems(documentNamespace, SpdxConstants.CLASS_SPDX_SNIPPET).forEach(element -> {
			if (elementIdLineNumberMap.containsKey(element.getId())) {
				;
				try {
					verifyElement(new SpdxSnippet(modelStore, documentNamespace, element.getId(), copyManager, false).verify(), "Snippet", elementIdLineNumberMap.get(element.getId()));
				} catch (InvalidSPDXAnalysisException e) {
					this.warningMessages.add("Exception verifying element "+element.getId()+": "+e.getMessage());
				}
			}
		});
		modelStore.getAllItems(documentNamespace, SpdxConstants.CLASS_SPDX_FILE).forEach(element -> {
			if (elementIdLineNumberMap.containsKey(element.getId())) {
				;
				try {
					verifyElement(new SpdxFile(modelStore, documentNamespace, element.getId(), copyManager, false).verify(), "File", elementIdLineNumberMap.get(element.getId()));
				} catch (InvalidSPDXAnalysisException e) {
					this.warningMessages.add("Exception verifying element "+element.getId()+": "+e.getMessage());
				}
			}
		});
		
		List<String> analysisVerify = analysis.verify();
		for (String analysisVerifyMsg:analysisVerify) {
			// add any missing messages
			boolean found = false;
			for (String warningMsg:warningMessages) {
				if (warningMsg.contains(analysisVerifyMsg)) {
					found = true;
					break;
				}
			}
			if (!found) {
				warningMessages.add(analysisVerifyMsg);
			}
		}
	}

	/**
	 * Makes sure there is a describes relationships for a single package
	 * SPDX document
	 * @throws InvalidSPDXAnalysisException
	 * @throws InvalidSpdxTagFileException
	 */
	private void checkSinglePackageDefault() throws InvalidSPDXAnalysisException, InvalidSpdxTagFileException {
		for (Relationship relationship:this.analysis.getRelationships()) {
			if (relationship.getRelationshipType() == RelationshipType.DESCRIBES) {
				return;	// We found at least one document describes, we don't need to add a default
			}
		}
		List<SpdxPackage> pkgs = new ArrayList<>();
		modelStore.getAllItems(documentNamespace, SpdxConstants.CLASS_SPDX_PACKAGE).forEach(element -> {
			try {
				pkgs.add(new SpdxPackage(modelStore, documentNamespace, element.getId(), copyManager, true));
			} catch (InvalidSPDXAnalysisException e) {
				warningMessages.add("Error adding default document describes: "+e.getMessage());
			}
		});
		if (pkgs.size() == 0) {
			throw new InvalidSpdxTagFileException("Missing describes relationship and there is no package to create a default - see SPDX specification relationship section under DESCRIBES relationship description for more information");
		}
		Relationship describesRelationship = analysis.createRelationship(pkgs.get(0), RelationshipType.DESCRIBES, 
				"This describes relationship was added as a default relationship by the SPDX Tools Tag parser.");
		this.analysis.addRelationship(describesRelationship);
	}

	/**
	 * @throws InvalidSPDXAnalysisException
	 *
	 */
	private void addAnnotations() throws InvalidSPDXAnalysisException {
		if (this.lastAnnotation != null) {
			this.annotations.add(lastAnnotation);
			lastAnnotation = null;
		}
		for (int i = 0; i < annotations.size(); i++) {
			String id = annotations.get(i).getId();
			if (id == null) {
				this.warningMessages.add("missing SPDXREF: tag in annotation " + annotations.get(i).getAnnotation().getComment() +
						" at line number "+annotations.get(i).getLineNumber());
				continue;
			}
			Optional<ModelObject> mo = SpdxModelFactory.getModelObject(modelStore, documentNamespace, id,  copyManager);
			if (!mo.isPresent()) {
				this.warningMessages.add("Invalid element reference in annotation: " + id + " at line number "+annotations.get(i).getLineNumber());
				continue;
			}
			SpdxElement element = null;
			try {
				element = (SpdxElement)mo.get();
			} catch(ClassCastException ex) {
				this.warningMessages.add("Invalid element reference in annotation: " + id + " at line number "+annotations.get(i).getLineNumber());
				continue;
			}
			verifyElement(annotations.get(i).getAnnotation().verify(), "Annotation", annotations.get(i).getLineNumber());
			element.getAnnotations().add(annotations.get(i).getAnnotation());
		}
	}

	/**
	 * @throws InvalidSPDXAnalysisException
	 *
	 */
	private void addRelationships() throws InvalidSPDXAnalysisException {
		if (this.lastRelationship != null) {
			this.relationships.add(lastRelationship);
			lastRelationship = null;
		}
		for (int i = 0; i < relationships.size(); i++) {
			RelationshipWithId relationship = relationships.get(i);
			String id = relationship.getId();
			Optional<ModelObject> mo = SpdxModelFactory.getModelObject(modelStore, documentNamespace, id,  copyManager);
			if (!mo.isPresent()) {
				this.warningMessages.add("Invalid element reference in relationship: " + id + " at line number "+relationship.getLineNumber());
				continue;
			}
			SpdxElement element = null;
			try {
				element = (SpdxElement)mo.get();
			} catch(ClassCastException ex) {
				this.warningMessages.add("Invalid element reference in relationship: " + id + " at line number "+relationship.getLineNumber());
				continue;
			}
			
			SpdxElement relatedElement = null;
			if (SpdxNoneElement.NONE_ELEMENT_ID.equals(relationship.getRelatedId())) {
				relatedElement = new SpdxNoneElement();
			} else if (SpdxNoAssertionElement.NOASSERTION_ELEMENT_ID.equals(relationship.getRelatedId())) {
				relatedElement = new SpdxNoAssertionElement();
			} else {
				Optional<ModelObject> relatedMo = SpdxModelFactory.getModelObject(modelStore, documentNamespace, relationship.getRelatedId(),  copyManager);
				if (!relatedMo.isPresent()) {
					this.warningMessages.add("Invalid related element reference in relationship: " + relationship.getRelatedId() + " at line number "+relationship.getLineNumber());
					continue;
				}
				try {
					relatedElement = (SpdxElement)relatedMo.get();
				} catch(ClassCastException ex) {
					this.warningMessages.add("Invalid related element reference in relationship: " + id + " at line number "+relationship.getLineNumber());
					continue;
				}
			}
			Relationship newRelationship = element.createRelationship(relatedElement, relationship.getRelationshipType(), 
					relationship.getComment());
			verifyElement(newRelationship.verify(), "Relationship", relationships.get(i).getLineNumber());
			element.addRelationship(newRelationship);
		}
	}

	/**
	 * Go through all of the file dependencies and snippet dependencies and add them to the file
	 * @throws InvalidSPDXAnalysisException
	 * @throws InvalidSpdxTagFileException
	 */
	@SuppressWarnings("deprecation")
	private void fixFileAndSnippetDependencies() throws InvalidSPDXAnalysisException, InvalidSpdxTagFileException,InvalidFileFormatException {
		// be prepared - it is complicate to make this efficient
		// the HashMap fileDependencyMap contains a map from a file name to all SPDX files which
		// reference that file name as a dependency
		// This method goes through all of the files in the analysis in a single pass and creates
		// a new HashMap of files (as the key) and the dependency files (arraylist) as the values.
		// We also take care of updating the files in the Snippet Dependencies in this pass.
		// Once that hashmap is built, the actual dependencies and snippets are then updated.
		// the key contains an SPDX file with one or more dependencies.  The value is the array list of file dependencies
		Map<SpdxFile, List<SpdxFile>> filesWithDependencies = new HashMap<>();
		Map<SpdxFile, List<SpdxSnippet>> filesWithSnippets = new HashMap<>();
		this.checkAnalysisNull();
		
		List<SpdxFile> allFiles = new ArrayList<>();
		SpdxModelFactory.getElements(modelStore, documentNamespace, copyManager, SpdxFile.class).forEach(file -> {
			allFiles.add((SpdxFile)file);
			if (modelStore.getIdType(((SpdxFile)file).getId()).equals(IdType.Anonymous)) {
				if (modelStore.getIdType(((SpdxFile)file).getId()).equals(IdType.Anonymous)) {
					this.warningMessages.add("Anonomous type was found for file");
				}
			}
		});
		
		// fill in the filesWithDependencies map
		for (int i = 0;i < allFiles.size(); i++) {
			String name = allFiles.get(i).getName().get();
			List<SpdxFile> alFilesHavingThisDependency = this.fileDependencyMap.get(name);
			if (alFilesHavingThisDependency != null) {
				for (int j = 0; j < alFilesHavingThisDependency.size(); j++) {
					SpdxFile fileWithDependency = alFilesHavingThisDependency.get(j);
					List<SpdxFile> alDepdenciesForThisFile = filesWithDependencies.get(fileWithDependency);
					if (alDepdenciesForThisFile == null) {
						alDepdenciesForThisFile = new ArrayList<>();
						filesWithDependencies.put(fileWithDependency, alDepdenciesForThisFile);
					}
					alDepdenciesForThisFile.add(allFiles.get(i));
				}
				// remove from the file dependency map so we can keep track of any files which did
				// not match at the end
				this.fileDependencyMap.remove(name);
			}
			List<SpdxSnippet> alSnippetsWithThisFile = this.snippetDependencyMap.get(allFiles.get(i).getId());
			if (alSnippetsWithThisFile != null) {
				List<SpdxSnippet> snippets = new ArrayList<>();
				filesWithSnippets.put(allFiles.get(i), snippets);
				for (SpdxSnippet snippet:alSnippetsWithThisFile) {
					snippets.add(snippet);
				}
			}
			this.snippetDependencyMap.remove(allFiles.get(i).getId());
		}
		// Go through the file dependency hashmap we just created and add the dependent files
		Iterator<Entry<SpdxFile, List<SpdxFile>>> iter = filesWithDependencies.entrySet().iterator();
		while (iter.hasNext()) {
			Entry<SpdxFile, List<SpdxFile>> entry = iter.next();
			List<SpdxFile> alDependencies = entry.getValue();
			if (alDependencies != null && alDependencies.size() > 0) {
				// Convert the dependencies to relationship
				SpdxFile fileWithDepdencies = entry.getKey();
				fileWithDepdencies.getFileDependency().addAll(alDependencies);
			}
		}
		// Now go through the snippets map
		Iterator<Entry<SpdxFile, List<SpdxSnippet>>> snIter = filesWithSnippets.entrySet().iterator();
		while (snIter.hasNext()) {
			Entry<SpdxFile, List<SpdxSnippet>> entry = snIter.next();
			List<SpdxSnippet> alSnippets = entry.getValue();
			if (alSnippets != null) {
				for (SpdxSnippet snippet:alSnippets) {
					snippet.setSnippetFromFile(entry.getKey());
					if (snippetByteRangeMap.containsKey(snippet)) {
						String value = snippetByteRangeMap.get(snippet);
						Matcher matcher = NUMBER_RANGE_PATTERN.matcher(value.trim());
						if (!matcher.find()) {
							throw(new InvalidSpdxTagFileException("Invalid snippet byte range: "+value));
						}
						int start = 0;
						try {
							start = Integer.parseInt(matcher.group(1));
						} catch (Exception ex) {
							throw new InvalidSpdxTagFileException("Non integer start to snippet byte offset: "+value);
						}
						int end = 0;
						try {
							end = Integer.parseInt(matcher.group(2));
						} catch (Exception ex) {
							throw new InvalidSpdxTagFileException("Non integer end to snippet byte offset: "+value);
						}
						snippet.setByteRange(start, end);
					}
					if (snippetLineRangeMap.containsKey(snippet)) {
						String value = snippetLineRangeMap.get(snippet);
						Matcher matcher = NUMBER_RANGE_PATTERN.matcher(value.trim());
						if (!matcher.find()) {
							throw(new InvalidSpdxTagFileException("Invalid snippet line range: "+ value));
						}
						int start = 0;
						try {
							start = Integer.parseInt(matcher.group(1));
						} catch (Exception ex) {
							throw new InvalidSpdxTagFileException("Non integer start to snippet line offset: "+value);
						}
						int end = 0;
						try {
							end = Integer.parseInt(matcher.group(2));
						} catch (Exception ex) {
							throw new InvalidSpdxTagFileException("Non integer end to snippet line offset: "+value);
						}
						snippet.setLineRange(start, end);
					}
				}
			}
		}
		// Check to see if there are any left over and and throw an error if the dependent files were
		// not found
		Set<String> missingDependencies = this.fileDependencyMap.keySet();
		if (missingDependencies != null && missingDependencies.size() > 0) {
			this.warningMessages.add("The following file names were listed as file dependencies but were not found in the list of files:");
			Iterator<String> missingIter = missingDependencies.iterator();
			while(missingIter.hasNext()) {
				this.warningMessages.add("\t"+missingIter.next());
			}
		}
		Set<String> missingSnippetFileIds = this.snippetDependencyMap.keySet();
		if (missingSnippetFileIds != null && missingSnippetFileIds.size() > 0) {
			this.warningMessages.add("The following file IDs were listed as files for snippets but were not found in the list of files:");
			Iterator<String> missingIter = missingDependencies.iterator();
			while(missingIter.hasNext()) {
				this.warningMessages.add("\t"+missingIter.next());
			}
		}
	}

	public String getDocumentUri() {
		return this.documentNamespace;
	}
}
