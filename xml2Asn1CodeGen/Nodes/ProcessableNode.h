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


#ifndef __PROCESSABLENODE_H__
#define __PROCESSABLENODE_H__

#pragma once

class File;
class SequenceNode;
class SetNode;
class EnumNode;
class ChoiceNode;
class BitstringNode;
class SequenceOfNode;
class FileNode;
class IDNode;
class NamedInt;

class ProcessableNode : public tsXmlNode
{
private:
	using tsXmlNode::Validate;
public:
	ProcessableNode() : _validated(false)
	{
	}
	virtual ~ProcessableNode() {}

	virtual tsStringBase Name() const { return _name; }
	virtual void Name(const tsStringBase& setTo) { _name = setTo; }
	virtual tsStringBase FullName() { return _name; }

	bool Validated() const { return _validated; }
	void Validated(bool setTo) { _validated = setTo; }
	virtual bool Validate() = 0;
	virtual bool Process() = 0;
	virtual tsStringBase BuildErrors(const tsStringBase& parentPath)
	{
		tsStringBase tmp;
		tsStringBase path;
		tsStringBase name;

		name = Name();
		if (name.size() == 0)
			name = Attributes().item("Name");

		path.append(parentPath).append("/").append(NodeName()).append("(").append(name).append(")");



		for (auto& warn : this->GetWarningList(false))
		{
			tmp.append("warning:  ").append(path).append('\n').append(warn->Description()).append('\n');
		}
		for (auto& warn : this->GetErrorList(false))
		{
			tmp.append("ERROR:  ").append(path).append('\n').append(warn->Description()).append('\n');
		}
		if (this->ChildrenCount() > 0)
		{
			for (auto& child : this->Children())
			{
				std::shared_ptr<ProcessableNode> pn = std::dynamic_pointer_cast<ProcessableNode>(child);
				if (!!pn)
					tmp.append(pn->BuildErrors(path));
			}
		}
		return tmp;
	}
	std::shared_ptr<IDNode> FindOID(const tsStringBase& elementType);
	std::shared_ptr<SequenceNode> FindSequence(const tsStringBase& elementType);
	std::shared_ptr<NamedInt> FindNamedInt(const tsStringBase& elementType);
	std::shared_ptr<EnumNode> FindEnum(const tsStringBase& elementType);
	std::shared_ptr<SetNode> FindSet(const tsStringBase& elementType);
	std::shared_ptr<ChoiceNode> FindChoice(const tsStringBase& elementType);
	std::shared_ptr<SequenceOfNode> FindSequenceOf(const tsStringBase& elementType);
	std::shared_ptr<BitstringNode> FindBitstring(const tsStringBase& elementType);
	std::shared_ptr<FileNode> GetFileNode();

protected:
	std::shared_ptr<IDNode> SearchChildrenForOID(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<SequenceNode> SearchChildrenForSequence(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<NamedInt> SearchChildrenForNamedInt(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<EnumNode> SearchChildrenForEnum(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<SetNode> SearchChildrenForSet(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<ChoiceNode> SearchChildrenForChoice(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<BitstringNode> SearchChildrenForBitstring(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);
	std::shared_ptr<SequenceOfNode> SearchChildrenForSequenceOf(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType);

	tsStringBase _name;
	bool _validated;

};

#endif // __PROCESSABLENODE_H__
