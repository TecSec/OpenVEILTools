//	Copyright (c) 2017, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

/*! @file tsXmlParser.h
 * @brief This file defines an XML parser that contains extended functionality used by the CKM Runtime
*/

#if !defined(__tsXMLPARSER_H__)
#define __tsXMLPARSER_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "tsXmlParserCallback.h"

/// <summary>An XML parser that uses a callback system to process the parsed data.  This is a SAX style parser.</summary>
class tsXmlParser
{
public:
	static void *operator new(std::size_t count) {
		return cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return cryptoNew(count);
	}
	static void operator delete(void *ptr) { cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { cryptoDelete(ptr); }

		/// <summary>Default constructor.</summary>
	tsXmlParser();
	/// <summary>Destructor.</summary>
	~tsXmlParser();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses the specified XML using the callback interface.</summary>
	///
	/// <param name="xml">	   The XML.</param>
	/// <param name="callback">[in] The callback interface.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Parse(const tsStringBase &xml, tsXmlParserCallback *callback, tsStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses the specified XML using the callback interface.</summary>
	///
	/// <param name="xml">	   The XML.</param>
	/// <param name="callback">[in] The callback interface.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Parse(const char *xml, tsXmlParserCallback *callback, tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parses the specified XML using the callback interface.</summary>
    /////
    ///// <param name="xml">	   The XML.</param>
    ///// <param name="len">	   The length of the XML.</param>
    ///// <param name="callback">[in] The callback interface.</param>
    ///// <param name="Results"> [in,out] The results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool Parse(const char *xml, size_t len, tsXmlParserCallback *callback, tsStringBase &Results);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	///// <summary>Object allocation operator.</summary>
	/////
	///// <param name="bytes">The number of bytes to allocate.</param>
	/////
	///// <returns>The allocated object.</returns>
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//void *operator new(size_t bytes);
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	///// <summary>Object de-allocation operator.</summary>
	/////
	///// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	//void operator delete(void *ptr);

protected:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses the XML.</summary>
	///
	/// <param name="Results">[in,out] The error results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlParserCallback::resultCodes Parse(tsStringBase &Results);


    static TSXmlParserCallbackResultCodes xml_processInstruction(void* params, const char* name, uint32_t nameLen, TSNAME_VALUE_LIST attributes, const char* contents, uint32_t contentsLen);
    static TSXmlParserCallbackResultCodes xml_startNode(void* params, const char* nodeName, uint32_t nodeNameLen, TSNAME_VALUE_LIST attributes, const char* innerXmlStart, const char* innerXmlEnd, ts_bool singleNode);
    static TSXmlParserCallbackResultCodes xml_endNode(void* params, const char* nodeName, uint32_t nodeNameLen);
    static TSXmlParserCallbackResultCodes xml_comment(void* params, const char* commentStart, const char* commentEnd);
    static TSXmlParserCallbackResultCodes xml_cdata(void* params, const char* cdataStart, const char* cdataEnd);
    static TSXmlParserCallbackResultCodes xml_text(void* params, const char* textStart, const char* textEnd);
    static TSXmlParserCallbackResultCodes xml_whitespace(void* params, const char* whitespaceStart, const char* whitespaceEnd);
    static void xml_reportError(void* params, const char* errorMessage);

    static TSXmlParserCallback gXmlCallbacks;



    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Removes whitespace from the current position of the internal XML string.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool EatWhitespace(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Eat whitespace without setting any errors.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool EatWhitespaceQuiet(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a doubly quoted string from the specified position in the XML buffer.</summary>
    /////
    ///// <param name="Start">  The starting point.</param>
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool ParseQuotedString(const char **Start, tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a name from the specified position in the XML buffer.</summary>
    /////
    ///// <param name="Start">  The starting point.</param>
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool ParseName(const char **Start, tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a node from the current position in the XML string.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseNode(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a text node from the current position in the XML string.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseTextNode(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse an attribute from the current position in the XML buffer.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseAttribute(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a comment from the current position in the XML buffer.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseComment(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a cdata definition from the current position in the XML buffer.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseCData(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a processing instruction from the current position in the XML buffer.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseProcessingInstruction(tsStringBase &Results);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Parse a metadata instruction from the current position in the XML buffer.</summary>
    /////
    ///// <param name="Results">[in,out] The error results.</param>
    /////
    ///// <returns>The parser error code for this tag.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsXmlParserCallback::resultCodes ParseMetadataInstruction(tsStringBase &Results);

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Query if 'c' is valid for the start of a name character.</summary>
    /////
    ///// <param name="c">The character to test.</param>
    /////
    ///// <returns>true if starting name character, false if not.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool IsStartingNameChar(char c);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Query if 'c' is valid for the second or later character in a name.</summary>
    /////
    ///// <param name="c">The character to test.</param>
    /////
    ///// <returns>true if name character, false if not.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool IsNameChar(char c);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Searches for the matching end node.</summary>
    /////
    ///// <param name="Name">			  The node name.</param>
    ///// <param name="EndNodePosition">[in,out] The end node position.</param>
    ///// <param name="EndNodeEnd">	  [in,out] The end node end.</param>
    ///// <param name="Results">		  [in,out] The error results.</param>
    /////
    ///// <returns>true if it succeeds, false if it fails.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //bool FindEndNode(const char *Name, size_t &EndNodePosition, size_t &EndNodeEnd, tsStringBase &Results);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Logs an error into the error string.</summary>
	///
	/// <param name="Results">[in,out] The error string.</param>
	/// <param name="number"> The error number.</param>
	/// <param name="value">  The error description.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void LogError(tsStringBase &Results, int32_t number, const char *value);
protected:

    tsStringBase m_results;
    //tsStringBase    			 m_xml;
    //size_t      		 m_position;
    //tsAttributeMap		 m_attributes;
	tsXmlParserCallback *m_callback;
    //uint32_t             m_nodeLevel;
    //uint32_t             m_regularNodeCountLevel1;
};

#endif

