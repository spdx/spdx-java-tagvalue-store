/**

 * Copyright (c) 2010 Source Auditor Inc.

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

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.SpdxConstants;
import org.spdx.library.model.Annotation;
import org.spdx.library.model.Checksum;
import org.spdx.library.model.ExternalDocumentRef;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxCreatorInformation;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxFile;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.SpdxPackageVerificationCode;
import org.spdx.library.model.SpdxSnippet;
import org.spdx.library.model.enumerations.FileType;
import org.spdx.library.model.enumerations.Purpose;
import org.spdx.library.model.license.AnyLicenseInfo;
import org.spdx.library.model.license.ExtractedLicenseInfo;
import org.spdx.library.model.license.SimpleLicensingInfo;
import org.spdx.library.model.pointer.ByteOffsetPointer;
import org.spdx.library.model.pointer.LineCharPointer;
import org.spdx.library.model.pointer.StartEndPointer;
import org.spdx.library.referencetype.ListedReferenceTypes;

/**
 * Define Common methods used by Tag-Value and SPDXViewer to print the SPDX
 * document.
 * 
 * @author Rana Rahal, Protecode Inc.
 */
public class CommonCode {
	
	static final Comparator<AnyLicenseInfo> LICENSE_COMPARATOR = new Comparator<AnyLicenseInfo>() {

		@Override
		public int compare(AnyLicenseInfo o1, AnyLicenseInfo o2) {
			return o1.toString().compareTo(o2.toString());
		}
		
	};
	
	static final Comparator<SpdxElement> ELEMENT_COMPARATOR = new Comparator<SpdxElement>() {

		@Override
		public int compare(SpdxElement arg0, SpdxElement arg1) {
			if (arg0 == null && arg1 == null) {
				return 0;
			} else if (arg0 == null) {
				return -1;
			} else if (arg1 == null) {
				return 1;
			} else {
				Optional<String> name0;
				try {
					name0 = arg0.getName();
				} catch (InvalidSPDXAnalysisException e) {
					name0 = Optional.empty();
				}
				Optional<String> name1;
				try {
					name1 = arg1.getName();
				} catch (InvalidSPDXAnalysisException e) {
					name1 = Optional.empty();
				}
				int retval = 0;
				if (name0.isPresent() && !name1.isPresent()) {
					retval = 1;
				} else if (name1.isPresent() && !name0.isPresent()) {
					retval = -1;
				} else if (name1.isPresent() && name0.isPresent()) {
					retval = name0.get().compareTo(name1.get());
				} else {
					retval = 0;
				}
				if (retval == 0) {
					// use the ID
					retval = arg0.getId().compareTo(arg1.getId());
				}
				return retval;
			}
		}
		
	};
	/**
	 * @param doc
	 * @param out
	 * @param constants
	 * @throws InvalidSPDXAnalysisException
	 */
	public static void printDoc(SpdxDocument doc, PrintWriter out,
			Properties constants) throws InvalidSPDXAnalysisException {
		if (doc == null) {
			println(out, "Warning: No document to print");
			return;
		}
		// version
		String spdxVersion = "";
		if (doc.getSpecVersion() != null
				&& doc.getCreationInfo().getCreated() != null) {
			spdxVersion = doc.getSpecVersion();
			println(out, constants.getProperty("PROP_SPDX_VERSION") + spdxVersion);
		}
		// Data license
		AnyLicenseInfo dataLicense = doc.getDataLicense();
		if (dataLicense != null) {
			if (dataLicense instanceof SimpleLicensingInfo) {
				println(out, constants.getProperty("PROP_SPDX_DATA_LICENSE")
						+ ((SimpleLicensingInfo)dataLicense).getLicenseId());
			} else {
				println(out, constants.getProperty("PROP_SPDX_DATA_LICENSE")
						+ dataLicense.toString());
			}
		}
		// Document Uri
		String docNamespace = doc.getDocumentUri();
		if (docNamespace != null && !docNamespace.isEmpty()) {
			out.println(constants.getProperty("PROP_DOCUMENT_NAMESPACE") + docNamespace);
		}
		// element properties
		printElementProperties(doc, out, constants, "PROP_DOCUMENT_NAME", "PROP_SPDX_COMMENT");
		println(out, "");
		// External References
		List<ExternalDocumentRef> externalRefs = new ArrayList<>(doc.getExternalDocumentRefs());
		if (externalRefs != null && !externalRefs.isEmpty()) {
			Collections.sort(externalRefs);
			String externalDocRefHedr = constants.getProperty("EXTERNAL_DOC_REFS_HEADER");
			if (externalDocRefHedr != null && !externalDocRefHedr.isEmpty()) {
				println(out, externalDocRefHedr);
			}
			for (ExternalDocumentRef externalRef:externalRefs) {
				printExternalDocumentRef(externalRef, out, constants);
			}
		}
		// Creators
		SpdxCreatorInformation creationInfo = doc.getCreationInfo();
		if (creationInfo != null) {
			List<String> creators = new ArrayList<>(creationInfo.getCreators());
			if (!creators.isEmpty()) {
				Collections.sort(creators);
				println(out, constants.getProperty("CREATION_INFO_HEADER"));
				for (String creator:creators) {
					println(out, constants.getProperty("PROP_CREATION_CREATOR")
							+ creator);
				}
			}
			// Creation Date
			if (creationInfo.getCreated() != null
					&& !creationInfo.getCreated().isEmpty()) {
				println(out, constants.getProperty("PROP_CREATION_CREATED")
						+ creationInfo.getCreated());
			}
			// Creator Comment
			Optional<String> creatorComment = creationInfo.getComment();
			if (creatorComment.isPresent()
					&& !creatorComment.get().isEmpty()) {
				println(out, constants.getProperty("PROP_CREATION_COMMENT")
						+ constants.getProperty("PROP_BEGIN_TEXT") 
						+ creatorComment.get()
						+ constants.getProperty("PROP_END_TEXT"));
			}
			// License list version
			Optional<String> licenseListVersion = creationInfo.getLicenseListVersion();
			if (licenseListVersion.isPresent() &&
					!licenseListVersion.get().isEmpty()) {
				println(out, constants.getProperty("PROP_LICENSE_LIST_VERSION") + 
				        licenseListVersion.get());
			}
		}
		printElementAnnotationsRelationships(doc, out, constants, "PROP_DOCUMENT_NAME", "PROP_SPDX_COMMENT");
		println(out, "");
		// Print the elements - need to print non-associated snippets, files before packages
		Set<SpdxFile> filesRemaining = new HashSet<>(); // files remaining to be printed
		try(@SuppressWarnings("unchecked")
		    Stream<SpdxFile> allFilesStream = (Stream<SpdxFile>) SpdxModelFactory.getElements(doc.getModelStore(), doc.getDocumentUri(),
				doc.getCopyManager(), SpdxFile.class)) {
		    allFilesStream.forEach((SpdxFile file) -> filesRemaining.add(file));
		}
		Set<SpdxSnippet> snippetsRemaining = new HashSet<>();
		try(@SuppressWarnings("unchecked")
	    Stream<SpdxSnippet> allSnippetssStream = (Stream<SpdxSnippet>) SpdxModelFactory.getElements(doc.getModelStore(), doc.getDocumentUri(),
			doc.getCopyManager(), SpdxSnippet.class)) {
			allSnippetssStream.forEach((SpdxSnippet snippet) -> snippetsRemaining.add(snippet));
		}
		Set<SpdxPackage> allPackages = new HashSet<>();
		try(@SuppressWarnings("unchecked")
            Stream<SpdxPackage> allPackagesStream = (Stream<SpdxPackage>) SpdxModelFactory.getElements(doc.getModelStore(), doc.getDocumentUri(),
                doc.getCopyManager(), SpdxPackage.class)) {
		    allPackagesStream.forEach((SpdxPackage pkg) -> {
		    		allPackages.add(pkg);
		    		// we need to remove any files that will be included in the packages
		    		try {
						pkg.getFiles().forEach((SpdxFile file) -> filesRemaining.remove(file));
					} catch (InvalidSPDXAnalysisException e) {
						throw new RuntimeException("Error getting files for a package", e);
					}
		    });
		}
		// first print out any described files or snippets
		List<SpdxElement> describedItems = new ArrayList<>(doc.getDocumentDescribes());
		Collections.sort(describedItems, ELEMENT_COMPARATOR);
		for (SpdxElement item:describedItems) {
			if (item instanceof SpdxFile) {
				printFile((SpdxFile)item, out, constants);
				filesRemaining.remove((SpdxFile)item);
			} else if (describedItems instanceof SpdxSnippet) {
				printSnippet((SpdxSnippet)item, out, constants);
				snippetsRemaining.remove((SpdxSnippet)item);
			}
		}
		// print any files which are not included package and not described
		ArrayList<SpdxFile> remainingFiles = new ArrayList<>(filesRemaining);
		Collections.sort(remainingFiles);
		remainingFiles.forEach((SpdxFile file) -> {
			try {
				printFile(file, out, constants);
			} catch (InvalidSPDXAnalysisException e) {
				out.println("Error printing file: "+e.getMessage());
			}
		});
		// Print any snippets not described
		ArrayList<SpdxSnippet> remainingSnippets = new ArrayList<>(snippetsRemaining);
		Collections.sort(remainingSnippets);
		remainingSnippets.forEach((SpdxSnippet snippet) -> {
            try {
                printSnippet(snippet, out, constants);
            } catch (InvalidSPDXAnalysisException e) {
                out.println("Error printing package: "+e.getMessage());
            }
        });
		// print any described packages
		for (SpdxElement item:describedItems) {
			if (item instanceof SpdxPackage) {
				printPackage((SpdxPackage)item, out, constants, doc.getDocumentUri());
			}
		}
		// print remaining packages
		ArrayList<SpdxPackage> remainingPackages = new ArrayList<>();
		allPackages.forEach((SpdxPackage pkg) -> {
			if (!describedItems.contains(pkg)) {
				remainingPackages.add(pkg);
			}
		});
		Collections.sort(remainingPackages);
		remainingPackages.forEach((SpdxPackage pkg) -> {
			try {
				printPackage(pkg, out, constants, doc.getDocumentUri());
			} catch (InvalidSPDXAnalysisException e) {
				out.println("Error printing package: "+e.getMessage());
			}
		});
		
		// Extracted license infos
		println(out, "");
		List<ExtractedLicenseInfo> extractedLicenseInfos = new ArrayList<>(doc.getExtractedLicenseInfos());
		if (!extractedLicenseInfos.isEmpty()) {
			Collections.sort(extractedLicenseInfos);
			println(out, constants.getProperty("LICENSE_INFO_HEADER"));
			for (ExtractedLicenseInfo extractedLicenseInfo:extractedLicenseInfos) {
				printLicense(extractedLicenseInfo, out, constants);
			}
		}
	}

	/**
	 * @param spdxSnippet
	 * @param out
	 * @param constants
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printSnippet(SpdxSnippet spdxSnippet, PrintWriter out,
			Properties constants) throws InvalidSPDXAnalysisException {
		println(out, constants.getProperty("SNIPPET_HEADER"));
		// NOTE: We can't call the print element properties since the order for tag/value is different for snippets
		println(out, constants.getProperty("PROP_SNIPPET_SPDX_ID") + spdxSnippet.getId());
		if (spdxSnippet.getSnippetFromFile() != null) {
			println(out, constants.getProperty("PROP_SNIPPET_FROM_FILE_ID") + 
					spdxSnippet.getSnippetFromFile().getId());
		}
		if (spdxSnippet.getByteRange() != null) {
			println(out, constants.getProperty("PROP_SNIPPET_BYTE_RANGE") + 
					formatPointerRange(spdxSnippet.getByteRange()));
		}
		Optional<StartEndPointer> lineRange = spdxSnippet.getLineRange();
		if (lineRange.isPresent()) {
			println(out, constants.getProperty("PROP_SNIPPET_LINE_RANGE") +
					formatPointerRange(lineRange.get()));
		}
		if (spdxSnippet.getLicenseConcluded() != null) {
			println(out, constants.getProperty("PROP_SNIPPET_CONCLUDED_LICENSE") +
					spdxSnippet.getLicenseConcluded());
		}
		if (spdxSnippet.getLicenseInfoFromFiles() != null) {
			List<AnyLicenseInfo> seenLicenses = new ArrayList<>(spdxSnippet.getLicenseInfoFromFiles());
			Collections.sort(seenLicenses, LICENSE_COMPARATOR);
			for (AnyLicenseInfo seenLicense:seenLicenses) {
				println(out, constants.getProperty("PROP_SNIPPET_SEEN_LICENSE") +
						seenLicense);
			}
		}
		Optional<String> licenseComment = spdxSnippet.getLicenseComments();
		if (licenseComment.isPresent() && !licenseComment.get().trim().isEmpty()) {
			println(out, constants.getProperty("PROP_SNIPPET_LIC_COMMENTS") +
			        licenseComment.get());
		}
		if (spdxSnippet.getCopyrightText() != null && !spdxSnippet.getCopyrightText().trim().isEmpty()) {
			String copyrightText = formatCopyrightText(constants, spdxSnippet.getCopyrightText());
			println(out, constants.getProperty("PROP_SNIPPET_COPYRIGHT") +
					copyrightText);
		}
		Optional<String> comment = spdxSnippet.getComment();
		if (comment.isPresent() && !comment.get().trim().isEmpty()) {
			println(out, constants.getProperty("PROP_SNIPPET_COMMENT") +
			        comment.get());
		}
		Optional<String> name = spdxSnippet.getName();
		if (name.isPresent() && !name.get().trim().isEmpty()) {
			println(out, constants.getProperty("PROP_SNIPPET_NAME") +
			        name.get());	
		}
		println(out, "");
	}

	/**
	 * Format a start end pointer into a numeric range
	 * @param pointer
	 * @return
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static String formatPointerRange(StartEndPointer pointer) throws InvalidSPDXAnalysisException {
		String start = "[MISSING]";
		String end = "[MISSING]";
		if (pointer.getStartPointer() != null) {
			if (pointer.getStartPointer() instanceof ByteOffsetPointer) {
				start = String.valueOf(((ByteOffsetPointer)(pointer.getStartPointer())).getOffset());
			} else if (pointer.getStartPointer() instanceof LineCharPointer) {
				start = String.valueOf(((LineCharPointer)(pointer.getStartPointer())).getLineNumber());
			}
		}
		if (pointer.getEndPointer() != null) {
			if (pointer.getEndPointer() instanceof ByteOffsetPointer) {
				end = String.valueOf(((ByteOffsetPointer)(pointer.getEndPointer())).getOffset());
			} else if (pointer.getStartPointer() instanceof LineCharPointer) {
				end = String.valueOf(((LineCharPointer)(pointer.getEndPointer())).getLineNumber());
			}
		}
		return start + ":" + end;
	}

	/**
	 * @param externalDocumentRef
	 * @param out
	 * @param constants
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printExternalDocumentRef(
			ExternalDocumentRef externalDocumentRef, PrintWriter out,
			Properties constants) throws InvalidSPDXAnalysisException {
		String uri = externalDocumentRef.getSpdxDocumentNamespace();
		if (uri == null || uri.isEmpty()) {
			uri = "[UNSPECIFIED]";
		}
		String sha1 = "[UNSPECIFIED]";
		Optional<Checksum> checksum = externalDocumentRef.getChecksum();
		if (checksum.isPresent() && checksum.get().getValue() != null && !checksum.get().getValue().isEmpty()) {
			sha1 = checksum.get().getValue();
		}
		String id = externalDocumentRef.getId();
		if (id == null || id.isEmpty()) {
			id = "[UNSPECIFIED]";
		}
		println(out, constants.getProperty("PROP_EXTERNAL_DOC_URI") +
					id + " " + uri + " SHA1: " + sha1);	
	}

	private static void printElementProperties(SpdxElement element,
			PrintWriter out, Properties constants, String nameProperty,
			String commentProperty) throws InvalidSPDXAnalysisException {
	    Optional<String> name = element.getName();
		if (name.isPresent() && !name.get().isEmpty()) {
			println(out, constants.getProperty(nameProperty) + name.get());
		}
		if (element.getId() != null && !element.getId().isEmpty()) {
			println(out, constants.getProperty("PROP_ELEMENT_ID") + element.getId());
		}
		Optional<String> comment = element.getComment();
		if (comment.isPresent() && !comment.get().isEmpty()) {
			println(out, constants.getProperty(commentProperty)
					+ constants.getProperty("PROP_BEGIN_TEXT")
					+ comment.get()
					+ constants.getProperty("PROP_END_TEXT"));
		}
	}

	private static void printElementAnnotationsRelationships(SpdxElement element,
			PrintWriter out, Properties constants, String nameProperty,
			String commentProperty) throws InvalidSPDXAnalysisException {
		List<Annotation> annotations = new ArrayList<>(element.getAnnotations());
		if (!annotations.isEmpty()) {
			Collections.sort(annotations);
			println(out, constants.getProperty("ANNOTATION_HEADER"));
			for (Annotation annotation:annotations) {
				printAnnotation(annotation, element.getId(), out, constants);
			}
		}
		List<Relationship> relationships = new ArrayList<>(element.getRelationships());
		if (!relationships.isEmpty()) {
		Collections.sort(relationships);
			println(out, constants.getProperty("RELATIONSHIP_HEADER"));
			for (Relationship relationship:relationships) {
				printRelationship(relationship, element.getId(), out, constants);
			}
		}
	}

	private static void printRelationship(Relationship relationship,
			String elementId, PrintWriter out, Properties constants) throws InvalidSPDXAnalysisException {
		String relatedElementId = "[MISSING]";
		Optional<SpdxElement> relatedElement = relationship.getRelatedSpdxElement();
		if (relatedElement.isPresent()) {
			relatedElementId = relatedElement.get().getId();
		}
		out.println(constants.getProperty("PROP_RELATIONSHIP")+
				elementId+" " +
				relationship.getRelationshipType().toString()+
				" " + relatedElementId);
	}

	/**
	 * @param annotation
	 * @param out
	 * @param constants
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printAnnotation(Annotation annotation, String id,
			PrintWriter out, Properties constants) throws InvalidSPDXAnalysisException {
		out.println(constants.getProperty("PROP_ANNOTATOR")+annotation.getAnnotator());
		out.println(constants.getProperty("PROP_ANNOTATION_DATE")+annotation.getAnnotationDate());
		out.println(constants.getProperty("PROP_ANNOTATION_COMMENT")
				+ constants.getProperty("PROP_BEGIN_TEXT")
				+ annotation.getComment()
				+ constants.getProperty("PROP_END_TEXT"));
		out.println(constants.getProperty("PROP_ANNOTATION_TYPE")+
				(annotation.getAnnotationType().toString()));
		out.println(constants.getProperty("PROP_ANNOTATION_ID")+id);
	}

	/**
	 * @param license
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printLicense(ExtractedLicenseInfo license,
			PrintWriter out, Properties constants) throws InvalidSPDXAnalysisException {
		// id
		if (license.getLicenseId() != null && !license.getLicenseId().isEmpty()) {
			println(out,
					constants.getProperty("PROP_LICENSE_ID") + license.getLicenseId());
		}
		if (license.getExtractedText() != null && !license.getExtractedText().isEmpty()) {
			println(out, constants.getProperty("PROP_EXTRACTED_TEXT") 
					+ constants.getProperty("PROP_BEGIN_TEXT")
					+ license.getExtractedText() + constants.getProperty("PROP_END_TEXT"));
		}
		if (license.getName() != null && !license.getName().isEmpty()) {
			println(out, constants.getProperty("PROP_LICENSE_NAME")+license.getName());
		}
		List<String> seeAlsos = new ArrayList<>(license.getSeeAlso());
		if (!seeAlsos.isEmpty()) {
			Collections.sort(seeAlsos);
			StringBuilder sb = new StringBuilder();
			boolean first = true;
			for (String seeAlso:seeAlsos) {
				if (first) {
					sb.append(seeAlso);
					first = false;
				} else {
					sb.append(", ");
					sb.append(seeAlso);
				}
			}
			println(out, constants.getProperty("PROP_SOURCE_URLS")+sb.toString());
		}
		if (license.getSeeAlso() != null) {
            if (license.getComment() != null && !license.getComment().isEmpty()) {
            	println(out, constants.getProperty("PROP_LICENSE_COMMENT")
            			+ constants.getProperty("PROP_BEGIN_TEXT")
            			+ license.getComment()
            			+ constants.getProperty("PROP_END_TEXT"));
            }
        }
		println(out, "");
	}


	private static void printPackage(SpdxPackage pkg, PrintWriter out,
			Properties constants, String documentNamespace) throws InvalidSPDXAnalysisException {
		println(out, constants.getProperty("PACKAGE_INFO_HEADER"));
		printElementProperties(pkg, out, constants,"PROP_PACKAGE_DECLARED_NAME",
				"PROP_PACKAGE_COMMENT");
		// Version
		Optional<String> version = pkg.getVersionInfo();
		if (version.isPresent()) {
			println(out,
					constants.getProperty("PROP_PACKAGE_VERSION_INFO")
							+ version.get());
		}
		// File name
		Optional<String> packageFileName = pkg.getPackageFileName();
		if (packageFileName.isPresent()) {
			println(out,
					constants.getProperty("PROP_PACKAGE_FILE_NAME")
							+ packageFileName.get());
		}
		// Supplier
		Optional<String> supplier = pkg.getSupplier();
		if (supplier.isPresent()) {
			println(out,
					constants.getProperty("PROP_PACKAGE_SUPPLIER")
							+ supplier.get());
		}
		// Originator
		Optional<String> originator = pkg.getOriginator();
		if (originator.isPresent()) {
			println(out,
					constants.getProperty("PROP_PACKAGE_ORIGINATOR")
							+ originator.get());
		}
		// Download location
		Optional<String> downloadLocation = pkg.getDownloadLocation();
		if (downloadLocation.isPresent()) {
			println(out,
					constants.getProperty("PROP_PACKAGE_DOWNLOAD_URL")
							+ downloadLocation.get());
		}
		// Primary Package Purpose
		Optional<Purpose> purpose = pkg.getPrimaryPurpose();
		if (purpose.isPresent()) {
			println(out, constants.getProperty("PROP_PRIMARY_PACKAGE_PURPOSE") + purpose.get().toString());
		}
		// release date
		Optional<String> releaseDate = pkg.getReleaseDate();
		if (releaseDate.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_RELEASE_DATE") + releaseDate.get());
		}
		// Built date
		Optional<String> builtDate = pkg.getBuiltDate();
		if (builtDate.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_BUILT_DATE") + builtDate.get());
		}
		// Valid until date
		Optional<String> validUntilDate = pkg.getValidUntilDate();
		if (validUntilDate.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_VALID_UNTIL_DATE") + validUntilDate.get());
		}
		// package verification code
		Optional<SpdxPackageVerificationCode> verificationCode = pkg.getPackageVerificationCode();
        if (verificationCode.isPresent()
                && verificationCode.get().getValue() != null
                && !verificationCode.get().getValue().isEmpty()) {
          String code = constants.getProperty("PROP_PACKAGE_VERIFICATION_CODE") + verificationCode.get().getValue();
          List<String> excludedFiles = new ArrayList<>(verificationCode.get().getExcludedFileNames());
          if (!excludedFiles.isEmpty()) {
        	  Collections.sort(excludedFiles);
              StringBuilder excludedFilesBuilder = new StringBuilder("(");
                
              for (String excludedFile : excludedFiles) {
                if(excludedFilesBuilder.length() > 1){
                    excludedFilesBuilder.append(", ");
                }
                
                excludedFilesBuilder.append(excludedFile);
              }
              
              excludedFilesBuilder.append(')');
              code += excludedFilesBuilder.toString();
          }                    
          println(out, code);
        }
		// Checksums
		List<Checksum> checksums = new ArrayList<>(pkg.getChecksums());
		if (!checksums.isEmpty()) {
			Collections.sort(checksums);
			for (Checksum checksum:checksums) {
				printChecksum(checksum, out, constants, "PROP_PACKAGE_CHECKSUM");
			}
		}
		// Home page
		Optional<String> homepage = pkg.getHomepage();
		if (homepage.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_HOMEPAGE_URL") + 
			        homepage.get());
		}
		// Source info
		Optional<String> sourceInfo = pkg.getSourceInfo();
		if (sourceInfo.isPresent()) {
			println(out, 
					constants.getProperty("PROP_PACKAGE_SOURCE_INFO")
							+ constants.getProperty("PROP_BEGIN_TEXT") 
							+ sourceInfo.get()
							+ constants.getProperty("PROP_END_TEXT"));
		}
		// concluded license
		if (pkg.getLicenseConcluded() != null) {
			println(out, constants.getProperty("PROP_PACKAGE_CONCLUDED_LICENSE")
					+ pkg.getLicenseConcluded());
		}
		// License information from files
		List<AnyLicenseInfo> licenses = new ArrayList<>(pkg.getLicenseInfoFromFiles());
		if (!licenses.isEmpty()) {
			Collections.sort(licenses, LICENSE_COMPARATOR);
			println(out, constants.getProperty("LICENSE_FROM_FILES_INFO_HEADER"));
			for (AnyLicenseInfo license:licenses) {
				println(out,
						constants
								.getProperty("PROP_PACKAGE_LICENSE_INFO_FROM_FILES")
								+ license.toString());
			}
		}
		// Declared licenses
		if (pkg.getLicenseDeclared() != null) {
			println(out, constants.getProperty("PROP_PACKAGE_DECLARED_LICENSE")
					+ pkg.getLicenseDeclared());
		}
		// License comments
		Optional<String> licenseComments = pkg.getLicenseComments();
		if (licenseComments.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_LICENSE_COMMENT")
					+ constants.getProperty("PROP_BEGIN_TEXT") 
					+ licenseComments.get() + 
					constants.getProperty("PROP_END_TEXT"));
		}
		// Declared copyright
		String copyrightText = formatCopyrightText(constants, pkg.getCopyrightText());
		if (copyrightText != null
				&& !pkg.getCopyrightText().isEmpty()) {
			print(out, constants.getProperty("PROP_PACKAGE_DECLARED_COPYRIGHT"));
			print(out, copyrightText);
			println(out, "");
		}
		// Short description
		Optional<String> summary = pkg.getSummary();
		if (summary.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_SHORT_DESC")
					+ constants.getProperty("PROP_BEGIN_TEXT") 
					+ summary.get() + constants.getProperty("PROP_END_TEXT"));
		}
		// Description
		Optional<String> description = pkg.getDescription();
		if (description.isPresent()) {
			println(out, constants.getProperty("PROP_PACKAGE_DESCRIPTION")
					+ constants.getProperty("PROP_BEGIN_TEXT") 
					+ description.get() + constants.getProperty("PROP_END_TEXT"));
		}
		// Attribution text
		if (!pkg.getAttributionText().isEmpty()) {
			pkg.getAttributionText().forEach(s -> {
				println(out, constants.getProperty("PROP_PACKAGE_ATTRIBUTION_TEXT")
						+ constants.getProperty("PROP_BEGIN_TEXT") 
						+ s + constants.getProperty("PROP_END_TEXT"));
			});
			
		}
		// External Refs
		List<ExternalRef> externalRefs = new ArrayList<>(pkg.getExternalRefs());
		if (!externalRefs.isEmpty()) {
			Collections.sort(externalRefs);
			for (ExternalRef externalRef:externalRefs) {
				printExternalRef(out, constants, externalRef, documentNamespace);
			}
		}
		printElementAnnotationsRelationships(pkg, out, constants,"PROP_PACKAGE_DECLARED_NAME",
				"PROP_PACKAGE_COMMENT");
		// Files
		if (!pkg.isFilesAnalyzed()) {
			// Only print if not the default
			println(out, constants.getProperty("PROP_PACKAGE_FILES_ANALYZED") + "false");
		}
		List<SpdxFile> files = new ArrayList<>(pkg.getFiles());
		if (!files.isEmpty()) {
            Collections.sort(files);                    
            println(out, "");
			println(out, constants.getProperty("FILE_INFO_HEADER"));
                        /* Print out sorted files */
			for (SpdxFile file : files) {
				printFile(file, out, constants);
				println(out, "");
			}
		} else {
			println(out, "");
		}
	}

	/**
	 * @param copyrightText
	 * @return
	 */
	private static String formatCopyrightText(Properties constants, String copyrightText) {
		boolean encloseInText = !(SpdxConstants.NONE_VALUE.equals(copyrightText) ||
				SpdxConstants.NOASSERTION_VALUE.equals(copyrightText));
		if (encloseInText) {
			return constants.getProperty("PROP_BEGIN_TEXT") + copyrightText + constants.getProperty("PROP_END_TEXT");
		} else {
			return copyrightText;
		}
	}

	/**
	 * Print a package ExternalRef to out
	 * @param out
	 * @param constants
	 * @param externalRef
	 * @param docNamespace
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printExternalRef(PrintWriter out, Properties constants,
			ExternalRef externalRef, String docNamespace) throws InvalidSPDXAnalysisException {
		String category = null;
		if (externalRef.getReferenceCategory() == null) {
			category = "OTHER";
		} else {
			category = externalRef.getReferenceCategory().toString().replace('_', '-');
		}
		String referenceType = null;
		if (externalRef.getReferenceType() == null) {
			referenceType = "[MISSING]";
		} else {
			try {
				try {
					referenceType = ListedReferenceTypes.getListedReferenceTypes().getListedReferenceName(new URI(externalRef.getReferenceType().getIndividualURI()));
				} catch (URISyntaxException e) {
					referenceType = "[Invalid URI]";
				} catch (InvalidSPDXAnalysisException e) {
					referenceType = null;
				}
				if (referenceType == null) {
					referenceType = externalRef.getReferenceType().getIndividualURI();
					if (referenceType.startsWith(docNamespace + "#")) {
						referenceType = referenceType.substring(docNamespace.length()+1);
					}
				}
			} catch (InvalidSPDXAnalysisException e) {
				referenceType = "[ERROR: "+e.getMessage()+"]";
			}
		}
		String referenceLocator = externalRef.getReferenceLocator();
		if (referenceLocator == null) {
			referenceLocator = "[MISSING]";
		}
		println(out, constants.getProperty("PROP_EXTERNAL_REFERENCE") + 
				category + " " + referenceType + " " + referenceLocator);
		Optional<String> comment = externalRef.getComment();
		if (comment.isPresent()) {
			println(out, constants.getProperty("PROP_EXTERNAL_REFERENCE_COMMENT") + 
			        comment.get());
		}
	}

	/**
	 * @param checksum
	 * @param out
	 * @param constants
	 * @param checksumProperty
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void printChecksum(Checksum checksum, PrintWriter out,
			Properties constants, String checksumProperty) throws InvalidSPDXAnalysisException {
		out.println(constants.getProperty(checksumProperty)
				+ checksum.getAlgorithm().toString().replaceAll("_", "-")
				+ ": " + checksum.getValue());
	}

	/**
	 * @param file
	 * @throws InvalidSPDXAnalysisException 
	 */
	@SuppressWarnings("deprecation")
	private static void printFile(SpdxFile file, PrintWriter out,
			Properties constants) throws InvalidSPDXAnalysisException {
		printElementProperties(file, out, constants, "PROP_FILE_NAME", 
				"PROP_FILE_COMMENT");
		// type
		List<FileType> fileTypes = new ArrayList<>(file.getFileTypes());
		if (!fileTypes.isEmpty()) {
			Collections.sort(fileTypes);
			for (FileType fileType:fileTypes) {
				println(out, constants.getProperty("PROP_FILE_TYPE") + fileType.toString());
			}
		}
		List<Checksum> checksums = new ArrayList<>(file.getChecksums());
		if (!checksums.isEmpty()) {
			Collections.sort(checksums);
			for (Checksum checksum:checksums) {
				printChecksum(checksum, out, constants, "PROP_FILE_CHECKSUM");
			}
		}
		// concluded license
		if (file.getLicenseConcluded() != null) {
			println(out, constants.getProperty("PROP_FILE_LICENSE")
					+ file.getLicenseConcluded().toString());
		}
		// License info in file
		List<AnyLicenseInfo> anyLicenseInfosFromFiles = new ArrayList<>(file.getLicenseInfoFromFiles());
		if (!anyLicenseInfosFromFiles.isEmpty()) {
			Collections.sort(anyLicenseInfosFromFiles, LICENSE_COMPARATOR);
			// print(out, "\tLicense information from file: ");
			// print(out, file.getSeenLicenses()[0].toString());
			for (AnyLicenseInfo license:anyLicenseInfosFromFiles) {
				println(out, constants.getProperty("PROP_FILE_SEEN_LICENSE")
						+ license.toString());
			}
		}
		// license comments
		Optional<String> licenseComments = file.getLicenseComments();
		if (licenseComments.isPresent()) {
			println(out,
					constants.getProperty("PROP_FILE_LIC_COMMENTS")
							+ licenseComments.get());
		}
		// file copyright
		if (file.getCopyrightText() != null && !file.getCopyrightText().isEmpty()) {
			String copyrightText = formatCopyrightText(constants, file.getCopyrightText());
			println(out, constants.getProperty("PROP_FILE_COPYRIGHT") 
					+ copyrightText);
		}
		// File notice
		Optional<String> noticeText = file.getNoticeText();
		if (noticeText.isPresent()) {
			println(out, constants.getProperty("PROP_FILE_NOTICE_TEXT") + 
					constants.getProperty("PROP_BEGIN_TEXT") +
					noticeText.get() + 
					constants.getProperty("PROP_END_TEXT"));
		}
		// file attribution text
		if (!file.getAttributionText().isEmpty()) {
			file.getAttributionText().forEach(s -> {
				println(out, constants.getProperty("PROP_FILE_ATTRIBUTION_TEXT")
						+ constants.getProperty("PROP_BEGIN_TEXT") 
						+ s + constants.getProperty("PROP_END_TEXT"));
			});
		}
		// file contributors
		List<String> fileContributors = new ArrayList<>(file.getFileContributors());
		if (!fileContributors.isEmpty()) {
			Collections.sort(fileContributors);
			for (String fileContributor:fileContributors) {
				println(out, constants.getProperty("PROP_FILE_CONTRIBUTOR")+
						fileContributor);
			}
		}
		List<SpdxFile> fileDependencies = new ArrayList<>(file.getFileDependency());
		Collections.sort(fileDependencies);
		for (SpdxFile fileDepdency : fileDependencies) {
		    Optional<String> depName = fileDepdency.getName();
		    String depFileName;
		    if (depName.isPresent()) {
		        depFileName = depName.get();
		    } else {
		        depFileName = "[MISSING]";
		    }
			println(out, constants.getProperty("PROP_FILE_DEPENDENCY") + depFileName);
		}
		printElementAnnotationsRelationships(file, out, constants, "PROP_FILE_NAME", 
				"PROP_FILE_COMMENT");
	}

	private static void println(PrintWriter out, String output) {
		if (out != null) {
			out.println(output);
		} else {
			System.out.println(output);
		}
	}
	
	private static void print(PrintWriter out, String output) {
		if (out != null) {
			out.print(output);
		} else {
			System.out.print(output);
		}
	}

	public static Properties getTextFromProperties(final String path)
			throws IOException {
		InputStream is = null;
		Properties prop = new Properties();
		try {
			is = CommonCode.class.getClassLoader().getResourceAsStream(path);
			prop.load(is);
		} finally {
			try {
				if (is != null) {
					is.close();
				}
			} catch (Throwable e) {
//				logger.warn("Unable to close properties file.");
			}
		}
		return prop;
	}

}