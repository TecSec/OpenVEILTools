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



// tsXmlError.cpp: implementation of the CtsXmlError class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ImportNode.h"
#include "FileNode.h"
#include "Asn1Export.h"

bool ImportNode::ReadText(const tsStringBase& filename, const tsStringBase& path, tsStringBase& contents)
{
	tsStringBase name;

	if (path.size() > 0)
	{
#ifdef _WIN32
		if (filename[1] == ':' || filename[0] == TS_PATH_SEP_CHAR)
		{
			return false;
		}
#else
		if (filename[0] == TS_PATH_SEP_CHAR)
		{
			return false;
		}
#endif
		name.append(path).append(filename);
	}
	else
		name = filename;
	return xp_ReadAllText(name, contents);
}
bool ImportNode::Validate() {
	if (Validated())
		return true;
	Validated(true);
	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);

		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}
	_exportFile = Asn1Export::CreateAsn1Export();
	_exportFile->fileNode = this->GetFileNode();

	tsStringBase contents;
	tsStringBase Results;
	tsStringBase filename = Attributes().item("Name");

	if (!ReadText(filename, "", contents) &&
		!ReadText(filename, gExportPath, contents) &&
		!ReadText(filename, gInputPath, contents) &&
		!ReadText(filename, gOutputPath, contents))
	{
		AddError("xml2Asn1CodeGen", "Validate", "Unable to read the export file " + filename);
		return false;
	}
	if (contents.empty())
	{
		AddError("xml2Asn1CodeGen", "Validate", "The export file " + filename + " is empty.");
		return false;
	}
	if (!_exportFile->Parse(contents, Results, false, false))
	{
		AddError("xml2Asn1CodeGen", "Validate", "Unable to parse the export file " + Attributes().item("Name") + ".");
		if (!Results.empty())
			AddError("xml2Asn1CodeGen", "Validate", "Results:  " + Results);
		AddError("xml2Asn1CodeGen", "Validate", _exportFile->Errors());
		return false;
	}

	if (!_exportFile->Validate())
	{
		AddError("xml2Asn1CodeGen", "Validate", "Unable to validate the export file " + Attributes().item("Name"));
		AddError("xml2Asn1CodeGen", "Validate", _exportFile->Errors());
		return false;
	}

	// TODO:  Move nodes here
	return true;
}

