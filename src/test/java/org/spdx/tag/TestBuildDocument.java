/**
 * SPDX-FileCopyrightText: Copyright (c) 2016 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.tag;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import org.spdx.core.IModelCopyManager;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.ModelRegistry;
import org.spdx.library.LicenseInfoFactory;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.Checksum;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.ModelObjectV2;
import org.spdx.library.model.v2.ReferenceType;
import org.spdx.library.model.v2.Relationship;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxElement;
import org.spdx.library.model.v2.SpdxFile;
import org.spdx.library.model.v2.SpdxModelInfoV2_X;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.SpdxSnippet;
import org.spdx.library.model.v2.enumerations.ChecksumAlgorithm;
import org.spdx.library.model.v2.enumerations.FileType;
import org.spdx.library.model.v2.enumerations.Purpose;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;
import org.spdx.library.model.v2.enumerations.RelationshipType;
import org.spdx.library.model.v2.license.SpdxNoAssertionLicense;
import org.spdx.library.model.v3_0_1.SpdxModelInfoV3_0;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;

import junit.framework.TestCase;


/**
 * @author Gary O'Neall
 */
public class TestBuildDocument extends TestCase {

	// Document level
	static final String SPDX_VERSION = "SPDX-2.3";
	static final String SPDX_VERSION_TAG = "SPDXVersion: " + SPDX_VERSION;
	static final String DOC_DATA_LICENSE = "CC0-1.0";
	static final String DOC_DATA_LICENSE_TAG = "DataLicense: " + DOC_DATA_LICENSE;
	static final String DOC_NAMESPACE = "http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301";
	static final String DOC_NAMESPACE_TAG = "DocumentNamespace: " + DOC_NAMESPACE;
	static final String DOC_NAME = "SPDX-Tools-v2.1";
	static final String DOC_NAME_TAG = "DocumentName: " + DOC_NAME;
	static final String DOC_SPDXID = "SPDXRef-DOCUMENT";
	static final String DOC_SPDXID_TAG = "SPDXID: " + DOC_SPDXID;
	static final String DOC_COMMENT = "Test document\ncomment";
	static final String DOC_COMMENT_TAG = "DocumentComment: <text>" + DOC_COMMENT + "</text>";
	static final String DOC_LEVEL_TAGS = SPDX_VERSION_TAG + "\n" + DOC_DATA_LICENSE_TAG + "\n" +
			DOC_NAMESPACE_TAG + "\n" + DOC_NAME_TAG + "\n" + DOC_SPDXID_TAG + "\n" +
			DOC_COMMENT_TAG;
	

	// External document references
	static final String EXTERNAL_DOC_REF_NAME = "DocumentRef-spdx-tool-1.2";
	static final String EXTERNAL_DOC_REF_URI = "http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301";
	static final String EXTERNAL_DOC_REF_SHA1 = "d6a770ba38583ed4bb4525bd96e50461655d2759";
	static final String EXTERNAL_DOC_REF_TAG = "ExternalDocumentRef: " + EXTERNAL_DOC_REF_NAME +
			" " + EXTERNAL_DOC_REF_URI + " SHA1: " + EXTERNAL_DOC_REF_SHA1;
	static final String EXTERNAL_DOC_REF_NAME2 = "DocumentRef-spdx-tool-2.0";
	    static final String EXTERNAL_DOC_REF2_URI = "http://spdx.org/spdxdocs/spdx-tools-v2.0-3F2504E0-4F89-41D3-9A0C-0305E82C3301";
	    static final String EXTERNAL_DOC_REF2_SHA1 = "aaa770ba38583ed4bb4525bd96e50461655d2759";
	    static final String EXTERNAL_DOC_REF2_TAG = "ExternalDocumentRef: " + EXTERNAL_DOC_REF_NAME2 +
	            " " + EXTERNAL_DOC_REF2_URI + " SHA1:" + EXTERNAL_DOC_REF2_SHA1;    // NOTE: No space between SHA1 and hash
	    static final String EXTERNAL_DOC_REF_TAGS = EXTERNAL_DOC_REF_TAG + "\n" + EXTERNAL_DOC_REF2_TAG;

	// Creator
	static final String CREATOR_TOOL = "Tool: LicenseFind-1.0";
	static final String CREATOR_TOOL_TAG = "Creator: " + CREATOR_TOOL;
	static final String CREATOR_ORGANIZATION = "Organization: ExampleCodeInspect ()";
	static final String CREATOR_ORGANIZATION_TAG = "Creator: " + CREATOR_ORGANIZATION;
	static final String CREATOR_PERSON = "Person: Jane Doe ()";
	static final String CREATOR_PERSON_TAG = "Creator: " + CREATOR_PERSON;
	static final String CREATED = "2010-01-29T18:30:22Z";
	static final String CREATED_TAG = "Created: " + CREATED;
	static final String CREATOR_COMMENT = "This package has been shipped in source and binary form.\n" +
			"The binaries were created with gcc 4.5.1 and expect to link to\n" +
			"compatible system run time libraries.";
	static final String CREATOR_COMMENT_TAG = "CreatorComment: <text>" + CREATOR_COMMENT + "</text>";
	static final String CREATOR_TAGS = CREATOR_TOOL_TAG + "\n" + CREATOR_ORGANIZATION_TAG + "\n" +
			CREATOR_PERSON_TAG + "\n" + CREATED_TAG + "\n" + CREATOR_COMMENT;

	// Document Annotation
	static final String DOC_ANNOTATOR = "Person: Jane Doe ()";
	static final String DOC_ANNOTATOR_TAG = "Annotator: " + DOC_ANNOTATOR;
	static final String DOC_ANNOTATION_DATE = "2010-01-29T18:30:22Z";
	static final String DOC_ANNOTATION_DATE_TAG = "AnnotationDate: " + DOC_ANNOTATION_DATE;
	static final String DOC_ANNOTATION_COMMENT = "Document level annotation";
	static final String DOC_ANNOTATION_COMMENT_TAG = "AnnotationComment: <text>" + DOC_ANNOTATION_COMMENT + "</text>";
	static final String DOC_ANNOTATION_TYPE = "OTHER";
	static final String DOC_ANNOTATION_TYPE_TAG = "AnnotationType: " + DOC_ANNOTATION_TYPE;
	static final String DOC_ANNOTATION_SPDXID_TAG = "SPDXREF: " + DOC_SPDXID;
	static final String DOC_ANNOTATION_TAGS = DOC_ANNOTATOR_TAG + "\n" + DOC_ANNOTATION_DATE_TAG + "\n" +
			DOC_ANNOTATION_COMMENT_TAG + "\n" + DOC_ANNOTATION_TYPE_TAG + "\n" +
			DOC_ANNOTATION_SPDXID_TAG;

	// Document Relationships
	static final String COPY_OF_RELATIONSHIP_TYPE = "COPY_OF";
	static final String COPY_OF_RELATIONSHIP = "DocumentRef-spdx-tool-1.2:SPDXRef-ToolsElement";
	static final String COPY_OF_RELATIONSHIP_TAG = "Relationship: " + DOC_SPDXID + " " + COPY_OF_RELATIONSHIP_TYPE + " " + COPY_OF_RELATIONSHIP;
	static final String CONTAINS_RELATIONSHIP_TYPE = "CONTAINS";
	static final String PACKAGE_SPDXID = "SPDXRef-Package";
	static final String CONTAINS_RELATIONSHIP = PACKAGE_SPDXID;
	static final String CONTAINS_RELATIONSHIP_TAG = "Relationship: " + DOC_SPDXID + " " + CONTAINS_RELATIONSHIP_TYPE + " " + CONTAINS_RELATIONSHIP;
	static final String DESCRIBES_RELATIONSHIP_TYPE = "DESCRIBES";
	static final String DESCRIBES_RELATIONSHIP = PACKAGE_SPDXID;
	static final String DESCRIBES_RELATIONSHIP_TAG = "Relationship: " + DOC_SPDXID + " " + DESCRIBES_RELATIONSHIP_TYPE + " " + DESCRIBES_RELATIONSHIP;
	static final String DOC_RELATIONSHIP_TAGS = COPY_OF_RELATIONSHIP_TAG + "\n" + CONTAINS_RELATIONSHIP_TAG + "\n" + DESCRIBES_RELATIONSHIP_TAG;

	// Package
	static final String PACKAGE_NAME = "glibc";
	static final String PACKAGE_NAME_TAG = "PackageName: " + PACKAGE_NAME;
	static final String PACKAGE_SPDXID_TAG = "SPDXID: " + PACKAGE_SPDXID;
	static final String PACKAGE_VERSION = "2.11.1";
	static final String PACKAGE_VERSION_TAG = "PackageVersion: " + PACKAGE_VERSION;
	static final String PACKAGE_FILENAME = "glibc-2.11.1.tar.gz";
	static final String PACKAGE_FILENAME_TAG = "PackageFileName: " + PACKAGE_FILENAME;
	static final String PACKAGE_SUPPLIER = "Person: Jane Doe (jane.doe@example.com)";
	static final String PACKAGE_SUPPLIER_TAG = "PackageSupplier: " + PACKAGE_SUPPLIER;
	static final String PACKAGE_ORIGINATOR = "Organization: ExampleCodeInspect (contact@example.com)";
	static final String PACKAGE_ORIGINATOR_TAG = "PackageOriginator: " + PACKAGE_ORIGINATOR;
	static final String PACKAGE_DOWNLOAD_LOCATION = "http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz";
	static final String PACKAGE_DOWNLOAD_LOCATION_TAG = "PackageDownloadLocation: " + PACKAGE_DOWNLOAD_LOCATION;
	static final String PACKAGE_VERIFICATION_CODE = "d6a770ba38583ed4bb4525bd96e50461655d2758";
	static final String PACKAGE_VERIFICATION_EXCLUDES = "(excludes: ./package.spdx)";
	static final String PACKAGE_VERIFICATION_TAG = "PackageVerificationCode: " + PACKAGE_VERIFICATION_CODE + " " +
			PACKAGE_VERIFICATION_EXCLUDES;
	static final String BUILT_DATE = "2011-01-29T18:30:22Z";
	static final String BUILT_DATE_TAG = "BuiltDate: " + BUILT_DATE;
	static final String RELEASE_DATE = "2012-01-29T18:30:22Z";
	static final String RELEASE_DATE_TAG = "ReleaseDate: " + RELEASE_DATE;
	static final String VALID_UNTIL_DATE = "2014-01-29T18:30:22Z";
	static final String VALID_UNTIL_DATE_TAG = "ValidUntilDate: " + VALID_UNTIL_DATE;
	static final String PACKAGE_CHECKSUM_SHA1 = "85ed0817af83a24ad8da68c2b5094de69833983c";
	static final String PACKAGE_CHECKSUM_SHA1_TAG = "PackageChecksum: SHA1: " + PACKAGE_CHECKSUM_SHA1;
	static final String PACKAGE_CHECKSUM_SHA256 = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd";
	static final String PACKAGE_CHECKSUM_SHA256_TAG = "PackageChecksum: SHA256: " + PACKAGE_CHECKSUM_SHA256;
	static final String PACKAGE_CHECKSUM_MD5 = "624c1abb3664f4b35547e7c73864ad24";
	static final String PACKAGE_CHECKSUM_MD5_TAG = "PackageChecksum: MD5: " + PACKAGE_CHECKSUM_MD5;
	static final String PACKAGE_CHECKSUM_BLAKE2B = "aaabd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706";
	static final String PACKAGE_CHECKSUM_BLAKE2B_TAG = "PackageChecksum: BLAKE2b-384: " + PACKAGE_CHECKSUM_BLAKE2B;
	static final String PACKAGE_HOME_PAGE = "http://ftp.gnu.org/gnu/glibc";
	static final String PACKAGE_HOME_PAGE_TAG = "PackageHomePage: " + PACKAGE_HOME_PAGE;
	static final String PACKAGE_SOURCE_INFO = "uses glibc-2_11-branch from git://sourceware.org/git/glibc.git.";
	static final String PACKAGE_SOURCE_INFO_TAG = "PackageSourceInfo: <text>" + PACKAGE_SOURCE_INFO + "</text>";
	static final String LICENSE_REF1 = "LicenseRef-1";
	static final String PACKAGE_LICENSE_CONCLUDED = "(" + LICENSE_REF1 + " OR LGPL-2.0-only)";
	static final String PACKAGE_LICENSE_CONCLUDED_TAG = "PackageLicenseConcluded: " + PACKAGE_LICENSE_CONCLUDED;
	static final String PACKAGE_LICENSE_INFO_FROM_FILES1 = "GPL-2.0-only";
	static final String PACKAGE_LICENSE_INFO_FROM_FILES1_TAG = "PackageLicenseInfoFromFiles: " + PACKAGE_LICENSE_INFO_FROM_FILES1;
	static final String PACKAGE_LICENSE_INFO_FROM_FILES2 = LICENSE_REF1;
	static final String PACKAGE_LICENSE_INFO_FROM_FILES2_TAG = "PackageLicenseInfoFromFiles: " + PACKAGE_LICENSE_INFO_FROM_FILES2;
	static final String LICENSE_REF2 = "LicenseRef-2";
	static final String PACKAGE_LICENSE_INFO_FROM_FILES3 = LICENSE_REF2;
	static final String PACKAGE_LICENSE_INFO_FROM_FILES3_TAG = "PackageLicenseInfoFromFiles: " + PACKAGE_LICENSE_INFO_FROM_FILES3;
	static final String PACKAGE_LICENSE_INFO_FROM_FILES_TAGS = PACKAGE_LICENSE_INFO_FROM_FILES1_TAG + "\n" +
			PACKAGE_LICENSE_INFO_FROM_FILES2_TAG + "\n" + PACKAGE_LICENSE_INFO_FROM_FILES3_TAG;
	static final String PACKAGE_LICENSE_DECLARED = "(" + LICENSE_REF2 + " AND LGPL-2.0-only)";
	static final String PACKAGE_LICENSE_DECLARED_TAG = "PackageLicenseDeclared: " + PACKAGE_LICENSE_DECLARED;
	static final String PACKAGE_LICENSE_COMMENT = "The license for this project changed with the release of version x.y.\n" +
			"The version of the project included here post-dates the license change.";
	static final String PACKAGE_LICENSE_COMMENT_TAG = "PackageLicenseComments: <text>" + PACKAGE_LICENSE_COMMENT + "</text>";
	static final String PACKAGE_COPYRIGHT = "Copyright 2008-2010 John Smith";
	static final String PACKAGE_COPYRIGHT_TAG = "PackageCopyrightText: <text>" + PACKAGE_COPYRIGHT + "</text>";
	static final String PACKAGE_SUMMARY = "GNU C library.";
	static final String PACKAGE_SUMMARY_TAG = "PackageSummary: <text>" + PACKAGE_SUMMARY + "</text>";
	static final String PACKAGE_DESCRIPTION = "The GNU C Library defines functions that are \n" +
			"specified by the ISO C standard, as well as additional features specific to \n" +
			"POSIX and other derivatives of the Unix operating system,\n" +
			" and extensions specific to GNU systems.";
	static final String PACKAGE_DESCRIPTION_TAG = "PackageDescription: <text>" + PACKAGE_DESCRIPTION + "</text>";
	static final String PACKAGE_PURPOSE = "SOURCE";
	static final String PACKAGE_PURPOSE_TAG = "PrimaryPackagePurpose: " + PACKAGE_PURPOSE;
	static final String EXTERNAL_REF_SECURITY_CATEGORY = "SECURITY";
	static final String EXTERNAL_REF_SECURITY_TYPE = "cpe23Type";
	static final String EXTERNAL_REF_SECURITY_LOCATOR = "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*";
	static final String PACKAGE_EXTERNAL_REF_SECURITY_TAG = "ExternalRef: " + EXTERNAL_REF_SECURITY_CATEGORY + " " +
			EXTERNAL_REF_SECURITY_TYPE + " " + EXTERNAL_REF_SECURITY_LOCATOR;
		static final String PACKAGE_EXTERNAL_REF_SECURITY_COMMENT = "external ref comment for security";
	static final String PACKAGE_EXTERNAL_REF_SECURITY_COMMENT_TAG = "ExternalRefComment: <text>" +
		PACKAGE_EXTERNAL_REF_SECURITY_COMMENT + "</text>";
	static final String PACKAGE_EXTERNAL_REF_OTHER_CATEGORY = "OTHER";
	static final String PACKAGE_EXTERNAL_REF_OTHER_TYPE = "LocationRefacmeforge";
	static final String PACKAGE_EXTERNAL_REF_OTHER_LOCATOR = "acmecorp/acmenator/4.1.3alpha";

	static final String PACKAGE_EXTERNAL_REF_OTHER_TAG = "ExternalRef: " + PACKAGE_EXTERNAL_REF_OTHER_CATEGORY +
			" " + PACKAGE_EXTERNAL_REF_OTHER_TYPE + " " + PACKAGE_EXTERNAL_REF_OTHER_LOCATOR;
	static final String PACKAGE_TAGS = PACKAGE_NAME_TAG + "\n" + PACKAGE_SPDXID_TAG + "\n" +
			PACKAGE_VERSION_TAG + "\n" + PACKAGE_FILENAME_TAG + "\n" +
			PACKAGE_SUPPLIER_TAG + "\n" + PACKAGE_ORIGINATOR_TAG + "\n" +
			BUILT_DATE_TAG + "\n" + RELEASE_DATE_TAG + "\n" + VALID_UNTIL_DATE_TAG + "\n" +
			PACKAGE_DOWNLOAD_LOCATION_TAG + "\n" + PACKAGE_VERIFICATION_TAG + "\n" +
			PACKAGE_CHECKSUM_SHA1_TAG + "\n" + PACKAGE_CHECKSUM_SHA256_TAG + "\n" +
			PACKAGE_CHECKSUM_MD5_TAG + "\n" + PACKAGE_CHECKSUM_BLAKE2B_TAG + "\n" + 
			PACKAGE_HOME_PAGE_TAG + "\n" +
			PACKAGE_SOURCE_INFO_TAG + "\n" + PACKAGE_LICENSE_CONCLUDED_TAG + "\n" +
			PACKAGE_LICENSE_INFO_FROM_FILES_TAGS + "\n" + PACKAGE_LICENSE_DECLARED_TAG + "\n" +
			PACKAGE_LICENSE_COMMENT_TAG + "\n" + PACKAGE_COPYRIGHT_TAG + "\n" +
			PACKAGE_SUMMARY_TAG + "\n" + PACKAGE_DESCRIPTION_TAG + "\n" + PACKAGE_PURPOSE_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_SECURITY_TAG + "\n" + PACKAGE_EXTERNAL_REF_SECURITY_COMMENT_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_OTHER_TAG;
	
	static final String PACKAGE_NO_FILES_TAG = "FilesAnalyzed: false";
	static final String PACKAGE_TAGS_NO_FILES = PACKAGE_NAME_TAG + "\n" + PACKAGE_SPDXID_TAG + "\n" +
			PACKAGE_VERSION_TAG + "\n" + PACKAGE_FILENAME_TAG + "\n" +
			PACKAGE_SUPPLIER_TAG + "\n" + PACKAGE_ORIGINATOR_TAG + "\n" +
			PACKAGE_DOWNLOAD_LOCATION_TAG + "\n" +
			PACKAGE_CHECKSUM_SHA1_TAG + "\n" + PACKAGE_CHECKSUM_SHA256_TAG + "\n" +
			PACKAGE_CHECKSUM_MD5_TAG + "\n" + PACKAGE_HOME_PAGE_TAG + "\n" +
			PACKAGE_SOURCE_INFO_TAG + "\n" + PACKAGE_LICENSE_CONCLUDED_TAG + "\n" +
			PACKAGE_LICENSE_COMMENT_TAG + "\n" + PACKAGE_COPYRIGHT_TAG + "\n" +
			PACKAGE_SUMMARY_TAG + "\n" + PACKAGE_DESCRIPTION_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_SECURITY_TAG + "\n" + PACKAGE_EXTERNAL_REF_SECURITY_COMMENT_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_OTHER_TAG + "\n" + PACKAGE_NO_FILES_TAG;
	
	static final String PACKAGE_TAGS_NO_LICENSE = PACKAGE_NAME_TAG + "\n" + PACKAGE_SPDXID_TAG + "\n" +
			PACKAGE_VERSION_TAG + "\n" + PACKAGE_FILENAME_TAG + "\n" +
			PACKAGE_SUPPLIER_TAG + "\n" + PACKAGE_ORIGINATOR_TAG + "\n" +
			PACKAGE_DOWNLOAD_LOCATION_TAG + "\n" +
			PACKAGE_CHECKSUM_SHA1_TAG + "\n" + PACKAGE_CHECKSUM_SHA256_TAG + "\n" +
			PACKAGE_CHECKSUM_MD5_TAG + "\n" + PACKAGE_HOME_PAGE_TAG + "\n" +
			PACKAGE_SOURCE_INFO_TAG + "\n" +
			PACKAGE_SUMMARY_TAG + "\n" + PACKAGE_DESCRIPTION_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_SECURITY_TAG + "\n" + PACKAGE_EXTERNAL_REF_SECURITY_COMMENT_TAG + "\n" +
			PACKAGE_EXTERNAL_REF_OTHER_TAG + "\n" + PACKAGE_NO_FILES_TAG;

	// File lib-source
	static final String FILE_LIB_FILENAME = "./lib-source/commons-lang3-3.1-sources.jar";
	static final String FILE_LIB_FILENAME_TAG = "FileName: " + FILE_LIB_FILENAME;
	static final String FILE_LIB_SPDXID = "SPDXRef-CommonsLangSrc";
	static final String FILE_LIB_SPDXID_TAG = "SPDXID: " + FILE_LIB_SPDXID;
	static final String FILE_LIB_COMMENT = "This file is used by Jena";
	static final String FILE_LIB_COMMENT_TAG = "FileComment: <text>" + FILE_LIB_COMMENT + "</text>";
	static final String FILE_LIB_FILE_TYPE = "ARCHIVE";
	static final String FILE_LIB_FILE_TYPE_TAG = "FileType: " + FILE_LIB_FILE_TYPE;
	static final String FILE_LIB_CHECKSUM = "c2b4e1c67a2d28fced849ee1bb76e7391b93f125";
	static final String FILE_LIB_CHECKSUM_TAG = "FileChecksum: SHA1: " + FILE_LIB_CHECKSUM;
	static final String FILE_LIB_LICENSE_CONCLUDED = "Apache-2.0";
	static final String FILE_LIB_LICENSE_CONCLUDED_TAG = "LicenseConcluded: " + FILE_LIB_LICENSE_CONCLUDED;
	static final String FILE_LIB_LICENSE_INFO = "Apache-1.1";
	static final String FILE_LIB_LICENSE_INFO_TAG = "LicenseInfoInFile: " + FILE_LIB_LICENSE_INFO;
	static final String FILE_LIB_LICENSE_COMMENT = "License comment for file lib";
	static final String FILE_LIB_LICENSE_COMMENT_TAG = "LicenseComments: " + FILE_LIB_LICENSE_COMMENT;
	static final String FILE_LIB_COPYRIGHT = "Copyright 2001-2011 The Apache Software Foundation";
	static final String FILE_LIB_COPYRIGHT_TAG = "FileCopyrightText: <text>" + FILE_LIB_COPYRIGHT + "</text>";
	static final String FILE_LIB_NOTICE = "Apache Commons Lang\n" +
			"Copyright 2001-2011 The Apache Software Foundation";
	static final String FILE_LIB_NOTICE_TAG = "FileNotice: <text>" + FILE_LIB_NOTICE + "</text>";
	static final String FILE_LIB_TAGS = FILE_LIB_FILENAME_TAG + "\n" + FILE_LIB_SPDXID_TAG + "\n" +
			FILE_LIB_COMMENT_TAG + "\n" + FILE_LIB_FILE_TYPE_TAG + "\n" + FILE_LIB_CHECKSUM_TAG + "\n" +
			FILE_LIB_LICENSE_CONCLUDED_TAG + "\n" + FILE_LIB_LICENSE_INFO_TAG + "\n" +
			FILE_LIB_LICENSE_COMMENT_TAG + "\n" + FILE_LIB_COPYRIGHT_TAG + "\n" + FILE_LIB_NOTICE_TAG;

	// Snippet libSnippet
	static final String SNIPPET_LIB_ID = "SPDXRef-Snippet";
	static final String SNIPPET_LIB_ID_TAG = "SnippetSPDXID: ";
	static final String SNIPPET_LIB_FROM_FILE_TAG = "SnippetFromFileSPDXID: " + FILE_LIB_SPDXID;
	static final int SNIPPET_LIB_BYTE_START = 310;
	static final int SNIPPET_LIB_BYTE_END = 420;
	static final String SNIPPET_LIB_BYTE_RANGE_TAG = "SnippetByteRange: " + String.valueOf(SNIPPET_LIB_BYTE_START) + ":" +
			String.valueOf(SNIPPET_LIB_BYTE_END);
	static final int SNIPPET_LIB_LINE_START = 5;
	static final int SNIPPET_LIB_LINE_END = 23;
	static final String SNIPPET_LIB_LINE_RANGE_TAG = "SnippetLineRange: " + String.valueOf(SNIPPET_LIB_LINE_START) + ":" +
			String.valueOf(SNIPPET_LIB_LINE_END);
	static final String SNIPPET_LIB_CONCLUDED_LICENSE = "GPL-2.0-only";
	static final String SNIPPET_LIB_CONCLUDED_LICENSE_TAG = "SnippetLicenseConcluded: " +
			SNIPPET_LIB_CONCLUDED_LICENSE;
	static final String SNIPPET_LIB_LICENSE_COMMENT = "Comment on snippet license";
	static final String SNIPPET_LIB_LICENSE_COMMENT_TAG = "SnippetLicenseComments: " +
			SNIPPET_LIB_LICENSE_COMMENT;
	static final String SNIPPET_LIB_LICENSE_INFO_IN_SNIPPET = "LGPL-2.0-only";
	static final String SNIPPET_LIB_LICENSE_INFO_IN_SNIPPET_TAG = "LicenseInfoInSnippet: " +
			SNIPPET_LIB_LICENSE_INFO_IN_SNIPPET;
	static final String SNIPPET_LIB_COPYRIGHT = "Copyright 20082010 John Smith";
	static final String SNIPPET_LIB_COPYRIGHT_TAG = "SnippetCopyrightText: " + SNIPPET_LIB_COPYRIGHT;
	static final String SNIPPET_LIB_COMMENT = "This snippet was identified as significant and highlighted in this Apache2.0\n" +
			"file, when a commercial scanner identified it as being derived from file foo.c in package xyz which is\n" +
			"licensed under GPL2.0.";
	static final String SNIPPET_LIB_COMMENT_TAG = "SnippetComment: <text>" + SNIPPET_LIB_COMMENT + "</text>";
	static final String SNIPPET_LIB_NAME = "from linux kernel";
	static final String SNIPPET_LIB_NAME_TAG = "SnippetName: " + SNIPPET_LIB_NAME;
	static final String SNIPPET_LIB_TAGS = SNIPPET_LIB_ID_TAG + SNIPPET_LIB_ID + "\n" + SNIPPET_LIB_FROM_FILE_TAG + "\n" +
			SNIPPET_LIB_BYTE_RANGE_TAG + "\n" + SNIPPET_LIB_LINE_RANGE_TAG + "\n" + SNIPPET_LIB_CONCLUDED_LICENSE_TAG + "\n" +
			SNIPPET_LIB_LICENSE_COMMENT_TAG + "\n" + SNIPPET_LIB_LICENSE_INFO_IN_SNIPPET_TAG + "\n" +
			SNIPPET_LIB_COPYRIGHT_TAG + "\n" + SNIPPET_LIB_COMMENT_TAG + "\n" + SNIPPET_LIB_NAME_TAG;

	// License Ref 1
	static final String LICENSE_REF1_LICENSEID_TAG = "LicenseID: " + LICENSE_REF1;
	static final String LICENSE_REF1_EXTRACTED_TEXT = "/*\n" +
			"* (c) Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Hewlett-Packard Development Company, LP\n" +
			"* All rights reserved.";
	static final String LICENSE_REF1_EXTRACTED_TEXT_TAG = "ExtractedText: <text>" + LICENSE_REF1_EXTRACTED_TEXT + "</text>";
	static final String LICENSE_REF1_TAGS = LICENSE_REF1_LICENSEID_TAG + "\n" + LICENSE_REF1_EXTRACTED_TEXT_TAG;

	// License Ref 2
	static final String LICENSE_REF2_LICENSEID_TAG = "LicenseID: " + LICENSE_REF2;
	static final String LICENSE_REF2_EXTRACTED_TEXT = "/*This package includes the GRDDL parser developed by Hewlett Pa";
	static final String LICENSE_REF2_EXTRACTED_TEXT_TAG = "ExtractedText: <text>" + LICENSE_REF2_EXTRACTED_TEXT + "</text>";
	static final String LICENSE_REF2_TAGS = LICENSE_REF2_LICENSEID_TAG + "\n" + LICENSE_REF2_EXTRACTED_TEXT_TAG;
	
	// License reference with no text
	static final String LICENSE_REF_NO_TEXT_TAGS = "LicenseID: " + LICENSE_REF2 + "\nLicenseName: Unlicense\n";

	String SIMPLE_TAGDOCUMENT = DOC_LEVEL_TAGS + "\n" + EXTERNAL_DOC_REF_TAGS + "\n" +
			CREATOR_TAGS + "\n" + DOC_ANNOTATION_TAGS + "\n" + DOC_RELATIONSHIP_TAGS + "\n" +
			PACKAGE_TAGS + "\n" + FILE_LIB_TAGS + "\n" + SNIPPET_LIB_TAGS + "\n" +
			LICENSE_REF1_TAGS + "\n" + LICENSE_REF2_TAGS;

	String TAGDOCUMENT_NO_FILES = DOC_LEVEL_TAGS + "\n" + EXTERNAL_DOC_REF_TAGS + "\n" +
			CREATOR_TAGS + "\n" + DOC_ANNOTATION_TAGS + "\n" + DOC_RELATIONSHIP_TAGS + "\n" +
			PACKAGE_TAGS_NO_FILES + "\n" + LICENSE_REF1_TAGS + "\n" +
			LICENSE_REF2_TAGS;
	
	String TAGDOCUMENT_NO_PACKAGE_LICENSE = DOC_LEVEL_TAGS + "\n" + EXTERNAL_DOC_REF_TAGS + "\n" +
			CREATOR_TAGS + "\n" + DOC_ANNOTATION_TAGS + "\n" + DOC_RELATIONSHIP_TAGS + "\n" +
			PACKAGE_TAGS_NO_LICENSE + "\n" + LICENSE_REF1_TAGS + "\n" +
			LICENSE_REF2_TAGS;
	
	String MISSING_TEXT_LICENSE_REF = "LicenseRef-Unlicense";
	
	String TAG_DOCUMENT_NO_EXTRACTED_TEXT = "SPDXVersion: SPDX-2.3\n" +
			"DataLicense: CC0-1.0\n" +
			"SPDXID: SPDXRef-DOCUMENT\n" +
			"DocumentName: SAG-PM generated SBOM\n" +
			"DocumentNamespace: "+DOC_NAMESPACE+"\n" +
			"Creator: Organization: dns:reliableenergyanalytics.com\n" +
			"Creator: Tool: SAG-PM Version: 1.2\n" +
			"Created: 2022-11-26T18:45:28Z\n" +
			"PackageName: apache-tomcat-9.0.69.zip\n" +
			"PackageVersion: 9.0.69\n" +
			"SPDXID: SPDXRef-Package-fc4a1bf0-78a0-43ca-b4a9-78adfb42138c\n" +
			"PackageSupplier: Organization: Apache Foundation\n" +
			"PackageDownloadLocation: https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.69/bin/apache-tomcat-9.0.69.zip/\n" +
			"FilesAnalyzed: false\n" +
			"LicenseID: "+MISSING_TEXT_LICENSE_REF+"\n"
			+ "LicenseName: Unlicense\n";

	IModelCopyManager copyManager;
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
		copyManager = new ModelCopyManager();
		ModelRegistry.getModelRegistry().registerModel(new SpdxModelInfoV2_X());
		ModelRegistry.getModelRegistry().registerModel(new SpdxModelInfoV3_0());
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	public void testBuildSimpleDocument() throws Exception {
		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		assertEquals(0, warnings.size());
		assertEquals(0, new SpdxDocument(modelStore, DOC_NAMESPACE, null, false).verify().size());
	}
	
	public void testNoExtractedText() throws Exception {
		InputStream bais = new ByteArrayInputStream(TAG_DOCUMENT_NO_EXTRACTED_TEXT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		assertEquals(1, warnings.size());
		assertTrue(warnings.get(0).contains(MISSING_TEXT_LICENSE_REF));
		List<String> verify = new SpdxDocument(modelStore, DOC_NAMESPACE, null, false).verify();
		assertEquals(1, verify.size());
		assertTrue(verify.get(0).contains(MISSING_TEXT_LICENSE_REF));
	}
	
	public void testPackagefiles() throws Exception {
		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		SpdxPackage pkg = new SpdxPackage(modelStore, DOC_NAMESPACE, PACKAGE_SPDXID, null, false);
		assertEquals(1, pkg.getFiles().size());
		for (SpdxFile spdxFile:pkg.getFiles()) {
			assertEquals(FILE_LIB_FILENAME, spdxFile.getName().get());
		}
		boolean foundContains = false;
		for (Relationship rel:pkg.getRelationships()) {
			if (rel.getRelationshipType() == RelationshipType.CONTAINS && 
					rel.getRelatedSpdxElement().get().getId().equals(FILE_LIB_SPDXID)) {
				assertFalse(foundContains);
				foundContains = true;
			}
		}
		assertFalse(modelStore.getValue(
				DOC_NAMESPACE + "#" + PACKAGE_SPDXID, 
				SpdxConstantsCompatV2.PROP_PACKAGE_FILE).isPresent());
	}
	
	public void testVersion2dot3noLicense() throws Exception {
		InputStream bais = new ByteArrayInputStream(TAGDOCUMENT_NO_PACKAGE_LICENSE.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		assertEquals(0, warnings.size());
		assertEquals(0, new SpdxDocument(modelStore, DOC_NAMESPACE, null, false).verify().size());
		SpdxPackage pkg = new SpdxPackage(modelStore, DOC_NAMESPACE, PACKAGE_SPDXID, null, false);
		// no license concluded
		assertEquals(new SpdxNoAssertionLicense(modelStore, DOC_NAMESPACE), pkg.getLicenseConcluded());
		// no copyright
		assertEquals("", pkg.getCopyrightText());
		// no license declared
		assertEquals(new SpdxNoAssertionLicense(modelStore, DOC_NAMESPACE), pkg.getLicenseDeclared());
	}
	
	public void testVersion2dot3() throws Exception {
		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		assertEquals(0, warnings.size());
		assertEquals(0, new SpdxDocument(modelStore, DOC_NAMESPACE, null, false).verify().size());
		SpdxPackage pkg = new SpdxPackage(modelStore, DOC_NAMESPACE, PACKAGE_SPDXID, null, false);
		// additional hash algorithms
		boolean foundHash = false;
		for (Checksum ck:pkg.getChecksums()) {
			if (ck.getAlgorithm().equals(ChecksumAlgorithm.BLAKE2b_384)) {
				foundHash = true;
			}
		}
		assertTrue(foundHash);
		// package purpose
		assertEquals(Purpose.SOURCE, pkg.getPrimaryPurpose().get());
		// release date
		assertEquals(RELEASE_DATE, pkg.getReleaseDate().get());
		// built date
		assertEquals(BUILT_DATE, pkg.getBuiltDate().get());
		// valid until date
		assertEquals(VALID_UNTIL_DATE, pkg.getValidUntilDate().get());
	}

	 public void testExternalRefs() throws Exception {
		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		SpdxDocument doc = new SpdxDocument(modelStore, DOC_NAMESPACE, null, false);
		SpdxPackage pkg = null;
		for (SpdxElement described:doc.getDocumentDescribes()) {
			pkg = (SpdxPackage)described;
		}
		Collection<ExternalRef> refs = pkg.getExternalRefs();
		assertEquals(2, refs.size());
		ExternalRef securityRef = doc.createExternalRef(ReferenceCategory.SECURITY,
				new ReferenceType(ListedReferenceTypes.getListedReferenceTypes().getListedReferenceUri(EXTERNAL_REF_SECURITY_TYPE).toString()),
				EXTERNAL_REF_SECURITY_LOCATOR, PACKAGE_EXTERNAL_REF_SECURITY_COMMENT);
		ExternalRef otherRef = doc.createExternalRef(ReferenceCategory.OTHER,
				new ReferenceType(DOC_NAMESPACE + "#" + PACKAGE_EXTERNAL_REF_OTHER_TYPE),
				PACKAGE_EXTERNAL_REF_OTHER_LOCATOR, null);
		Collection<ExternalRef> expected = Arrays.asList(new ExternalRef[] {securityRef, otherRef});
		assertTrue(collectionsEquivalent(expected, refs));
	}
	 
	 boolean collectionsEquivalent(Collection<? extends ModelObjectV2> a, Collection<? extends ModelObjectV2> b) throws InvalidSPDXAnalysisException {
		if (a.size() != b.size()) {
			return false;
		}
		for (ModelObjectV2 aItem: a) {
			boolean found = false;
			for (ModelObjectV2 bItem:b) {
				if (aItem.equivalent(bItem)) {
					found = true;
					break;
				}
			}
			if (!found) {
				return false;
			}
		}
		return true;
	 }

	
	public void testNoFilesAnalyzedFiles()  throws Exception {
		InputStream bais = new ByteArrayInputStream(TAGDOCUMENT_NO_FILES.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		assertEquals(0, warnings.size());
		assertEquals(0, new SpdxDocument(modelStore, DOC_NAMESPACE, null, false).verify().size());
		SpdxDocument doc = new SpdxDocument(modelStore, DOC_NAMESPACE, null, false);
		SpdxPackage pkg = null;
		for (SpdxElement described:doc.getDocumentDescribes()) {
			pkg = (SpdxPackage)described;
		}
		assertFalse(pkg.isFilesAnalyzed());
	}

	
	public void testFile()  throws Exception {
		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		List<SpdxFile> files = new ArrayList<>();
		try(@SuppressWarnings("unchecked")
		
        Stream<SpdxFile> fileStream = (Stream<SpdxFile>)SpdxModelFactory.getSpdxObjects(modelStore, null, 
        		SpdxConstantsCompatV2.CLASS_SPDX_FILE, DOC_NAMESPACE, null)) {
		    fileStream.forEach(element -> {
		        files.add((SpdxFile)element);
		    });
		}
		assertEquals(1, files.size());
		SpdxFile expected = new SpdxFile(modelStore, DOC_NAMESPACE, FILE_LIB_SPDXID, null, false);
		expected.setName(FILE_LIB_FILENAME);
		expected.setComment(FILE_LIB_COMMENT);
		expected.setLicenseConcluded(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(FILE_LIB_LICENSE_CONCLUDED, modelStore, DOC_NAMESPACE, copyManager));
		expected.getLicenseInfoFromFiles().add(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(FILE_LIB_LICENSE_INFO, modelStore, DOC_NAMESPACE, copyManager));
		expected.setCopyrightText(FILE_LIB_COPYRIGHT);
		expected.setLicenseComments(FILE_LIB_LICENSE_COMMENT);
		expected.getFileTypes().add(FileType.ARCHIVE);
		expected.getChecksums().add(expected.createChecksum(ChecksumAlgorithm.SHA1, FILE_LIB_CHECKSUM));
		expected.setNoticeText(FILE_LIB_NOTICE);
		assertTrue(expected.equivalent(files.get(0)));
	}

	
	public void testSnippet()  throws Exception {

		InputStream bais = new ByteArrayInputStream(SIMPLE_TAGDOCUMENT.getBytes());
		HandBuiltParser parser = new HandBuiltParser(new NoCommentInputStream(bais));
		List<String> warnings = new ArrayList<>();
		Properties constants = CommonCode.getTextFromProperties("org/spdx/tag/SpdxTagValueConstants.properties");
		IModelStore modelStore = new InMemSpdxStore();
		parser.setBehavior(new BuildDocument(modelStore, constants, warnings));
		parser.data();
		List<SpdxSnippet> snippets = new ArrayList<>();
		try(@SuppressWarnings("unchecked")
        Stream<SpdxSnippet> snippetStream = (Stream<SpdxSnippet>)SpdxModelFactory.getSpdxObjects(modelStore, 
        		null, SpdxConstantsCompatV2.CLASS_SPDX_SNIPPET, DOC_NAMESPACE, null)) {
		    snippetStream.forEach(element -> {
		        snippets.add((SpdxSnippet)element);
		    });
		}
		assertEquals(1, snippets.size());
		SpdxFile snippetFromFile = new SpdxFile(modelStore, DOC_NAMESPACE, FILE_LIB_SPDXID, null, false);
		snippetFromFile.setName(FILE_LIB_FILENAME);
		snippetFromFile.setComment(FILE_LIB_COMMENT);
		snippetFromFile.setLicenseConcluded(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(FILE_LIB_LICENSE_CONCLUDED, modelStore, DOC_NAMESPACE, copyManager));
		snippetFromFile.getLicenseInfoFromFiles().add(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(FILE_LIB_LICENSE_INFO, modelStore, DOC_NAMESPACE, copyManager));
		snippetFromFile.setCopyrightText(FILE_LIB_COPYRIGHT);
		snippetFromFile.setLicenseComments(FILE_LIB_LICENSE_COMMENT);
		snippetFromFile.getFileTypes().add(FileType.ARCHIVE);
		snippetFromFile.getChecksums().add(snippetFromFile.createChecksum(ChecksumAlgorithm.SHA1, FILE_LIB_CHECKSUM));
		snippetFromFile.setNoticeText(FILE_LIB_NOTICE);

		SpdxSnippet expected = new SpdxSnippet(modelStore, DOC_NAMESPACE, SNIPPET_LIB_ID, null, false);
		expected.setName(SNIPPET_LIB_NAME);
		expected.setComment(SNIPPET_LIB_COMMENT);
		expected.setLicenseConcluded(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(SNIPPET_LIB_CONCLUDED_LICENSE, modelStore, DOC_NAMESPACE, copyManager));
		expected.getLicenseInfoFromFiles().add(LicenseInfoFactory.parseSPDXLicenseStringCompatV2(SNIPPET_LIB_LICENSE_INFO_IN_SNIPPET, modelStore, DOC_NAMESPACE, copyManager));
		expected.setCopyrightText(SNIPPET_LIB_COPYRIGHT);
		expected.setLicenseComments(SNIPPET_LIB_LICENSE_COMMENT);
		expected.setSnippetFromFile(snippetFromFile);
		expected.setByteRange(SNIPPET_LIB_BYTE_START, SNIPPET_LIB_BYTE_END);
		expected.setLineRange(SNIPPET_LIB_LINE_START, SNIPPET_LIB_LINE_END);
		assertTrue(expected.equivalent(snippets.get(0)));
	}

}
