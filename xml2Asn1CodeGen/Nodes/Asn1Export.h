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



#ifndef __Asn1Export_H__
#define __Asn1Export_H__

#pragma once

#include "FileNode.h"

class Asn1Export : public ProcessableNode
{
public:
	static std::shared_ptr<Asn1Export> CreateAsn1Export() { return IObject::Create<Asn1Export>(); }
	Asn1Export();
	~Asn1Export();

	static std::shared_ptr<tsXmlNode>Create() { return IObject::Create<Asn1Export>(); }
	std::shared_ptr<FileNode> fileNode;

	virtual bool Validate() override
	{ 
		if (Validated())
			return true;
		Validated(true);
		for (size_t i = 0; i < Children().size(); i++)
		{
			std::shared_ptr<tsXmlNode> node = Children().at(i);
			std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
			if (!pNode || !pNode->Validate())
				return false;
		}
		return true;
	}
	virtual bool Process() override;
	tsStringBase Errors()
	{
		return BuildErrors("");
	}

protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;

protected:
	tsXmlParserCallback::resultCodes CData(const tsStringBase & Contents,
		tsStringBase &/*Results*/) override
	{
		if (m_RunnableParseNode->NodeText().size() > 0)
			m_RunnableParseNode->AppendText("\r\n");
		m_RunnableParseNode->AppendText(Contents);
		return tsXmlParserCallback::rcSuccess;
	}
};



#endif // __Asn1Export_H__
