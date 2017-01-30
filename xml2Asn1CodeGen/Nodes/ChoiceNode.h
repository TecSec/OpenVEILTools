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



#ifndef __CHOICENODE_H__
#define __CHOICENODE_H__

#pragma once

#include "TaggedElement.h"
#include "ElementContainer.h"
#include "FunctionNode.h"

class ChoiceNode : public TaggedElement, public ElementContainer
{
public:
	ChoiceNode()
	{
		ElementType("Choice");
	}
	virtual ~ChoiceNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;
	virtual tsStringBase FullName() override;
	virtual tsStringBase FullStructureName() override;

	virtual tsStringBase StructureName() const override { return Element::StructureName(); }
	virtual void StructureName(const tsStringBase& setTo) override { Element::StructureName(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return Element::NameSpace(); }
	virtual tsStringBase NameForParent() override { return StructureName(); }

	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) override;
	virtual bool WritePODStructure(std::shared_ptr<FileNode> files) override;
	virtual bool WriteStructure(std::shared_ptr<FileNode> files) override;
	virtual bool WritePODFieldDefinition(std::shared_ptr<FileNode> files) override;
	virtual bool WriteToJSON(File* file) override;
	virtual bool WriteFromJSON(File* file) override;
	virtual tsStringBase BuildMoveLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildClearForMove(const tsStringBase& rightObject) override;

	std::vector<std::shared_ptr<Element>>& FieldMetadataDependencies() { return _fieldMetadataDependencies; }
	std::vector<std::shared_ptr<FunctionNode>>& Functions() { return _functions; }

	virtual bool usesSeparateClass() const override { return true; }
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
protected:
	std::vector<std::shared_ptr<Element>> _fieldMetadataDependencies;
	std::vector<std::shared_ptr<FunctionNode>> _functions;

	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;
	bool _WriteUserFunctions(File* file);

	tsStringBase buildInitializers(InitializerType type);
};

#endif // __CHOICENODE_H__
