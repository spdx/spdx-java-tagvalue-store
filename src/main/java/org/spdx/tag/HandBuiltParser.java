/**
 * SPDX-FileCopyrightText: Copyright (c) 2013 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
*/
package org.spdx.tag;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * I'm hoping this is a temporary solution.  This is a hand built parser to parse
 * SPDX tag files.  It replaces the current ANTL based parser which has a defect
 * where any lines starting with a text ending with a : is treated as a tag even
 * if it is in <code>&lt;text&gt; &lt;/text&gt;</code>.
 *
 * The interface is similar to the generated ANTLR code.
 *
 * @author Gary O'Neall
 */
public class HandBuiltParser {

	private static final String END_TEXT = "</text>";
	private static final String START_TEXT = "<text>";
	Pattern tagPattern = Pattern.compile("^\\w+:");
	private TagValueBehavior buildDocument;
	private NoCommentInputStream textInput;

	/**
	 * Creates a parser for an Input stream.
	 * The input stream must not use any comments.
	 * @param textInput
	 */
	public HandBuiltParser(NoCommentInputStream textInput) {
		this.textInput = textInput;
	}

	/**
	 * @param buildDocument
	 */
	public void setBehavior(TagValueBehavior buildDocument) {
		this.buildDocument = buildDocument;
	}

	/**
	 * parses the data
	 * @throws Exception
	 */
	public void data() throws Exception {
		try {
			boolean inTextBlock = false;
			String tag = "";
			String value = "";
			String nextLine = textInput.readLine();
			while (nextLine != null) {
				if (inTextBlock) {
					if (nextLine.indexOf(START_TEXT)>0){
						throw(new RecognitionException("Found a text block inside another text block at line " +
									(textInput.getCurrentLineNo()) + ".  Expecting "+END_TEXT));
					}
					int endText = nextLine.indexOf(END_TEXT);
					if (endText >= 0) {
						value = value + "\n" + nextLine.substring(0, endText).trim();
						inTextBlock = false;	//NOTE: we are skipping any text after the </text>
						this.buildDocument.buildDocument(tag, value, textInput.getCurrentLineNo());
						tag = "";
						value = "";
					} else {
						value = value + "\n" + nextLine;
					}
				} else {
					// not in a text block
					Matcher tagMatcher = this.tagPattern.matcher(nextLine);
					if (tagMatcher.find()) {
						tag = tagMatcher.group();
						int startText = nextLine.indexOf(START_TEXT);
						if (startText > 0) {
							value = nextLine.substring(startText + START_TEXT.length()).trim();
							if (value.contains(END_TEXT)) {
								value = value.substring(0, value.indexOf(END_TEXT)).trim();
								this.buildDocument.buildDocument(tag, value, textInput.getCurrentLineNo());
								tag = "";
								value = "";
							} else {
								inTextBlock = true;
							}
						} else {
							value = nextLine.substring(tag.length()).trim();
							this.buildDocument.buildDocument(tag, value, textInput.getCurrentLineNo());
							tag = "";
							value = "";

						}
					} else {
						// note - we just ignore any lines that do not start with a tag
					}
				}
				nextLine = textInput.readLine();
			}
			if (inTextBlock) {
				throw(new RecognitionException("Unterminated text block at line " + (textInput.getCurrentLineNo()) + " Expecting "+END_TEXT ));
			}
			this.buildDocument.exit();
		} finally {
			textInput.close();
		}
	}


}
