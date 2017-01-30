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



#ifndef __FUNCTIONNODE_H__
#define __FUNCTIONNODE_H__

#pragma once

class FunctionNode : public ProcessableNode
{
public:
	FunctionNode()
	{
	}
	virtual ~FunctionNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;

	tsStringBase ReturnType() const { return _returnType; }
	void ReturnType(const tsStringBase& setTo) { _returnType = setTo; }
	tsStringBase Parameters() const { return _parameters; }
	void Parameters(const tsStringBase& setTo) { _parameters = setTo; }
	tsStringBase Suffix() const { return _suffix; }
	void Suffix(const tsStringBase& setTo) { _suffix = setTo; }
	tsStringBase Body() { return NodeText(); }
	tsStringBase Description() const
	{
		const std::shared_ptr<tsXmlNode> node = ChildByName("Description");

		if (!node)
			return "";
		return node->NodeText();
	}


protected:
	tsStringBase _returnType;
	tsStringBase _parameters;
	tsStringBase _suffix;

	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;
private:
    using ProcessableNode::CreateNode;
};

#endif // __FUNCTIONNODE_H__
