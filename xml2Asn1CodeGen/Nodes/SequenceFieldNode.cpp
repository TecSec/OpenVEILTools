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
#include "SequenceFieldNode.h"
#include "DescriptionNode.h"
#include "FileNode.h"

bool SequenceFieldNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Sequence Field is missing the Name attribute.\n");
		return false;
	}
	if (!Attributes().hasItem("ElementType"))
	{
		AddError("xml2Asn1CodeGen", "", "Sequence Field is missing the ElementType attribute.\n");
		return false;
	}

	SequenceName(Attributes().item("ElementType"));
	Element::StructureName(SequenceName());
	Default(Attributes().item("Default"));
	Initializer(Attributes().item("Initializer"));
	Name(Attributes().item("Name"));
	Type(Attributes().item("Type"));
	Tag(Attributes().item("Tag"));
	JSONName(Attributes().item("JSONName"));



	CppType(SequenceName());
	IsOptional(Attributes().itemAsBoolean("Optional", false));


	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}
	_linkedSequence = FindSequence(/*Attributes().item("ElementType").split(":")->back()*/ StructureName());
	if (!!_linkedSequence)
	{
		if (!!ParentSequence())
		{
			ParentSequence()->AddDependency(_linkedSequence);
		}
		else if (!!ParentSequenceOf())
		{
			ParentSequenceOf()->AddDependency(_linkedSequence);
		}
		else if (!!ParentChoice())
		{
			ParentChoice()->AddDependency(_linkedSequence);
		}
		_namespace = _linkedSequence->NameSpace();
	}
	//}

	if (!_linkedSequence)
	{
		AddError("xml2Asn1CodeGen", "", "Sequence:ElementType does not refer to a Sequence element:  " + Attributes().item("ElementType"));
		return false;
	}
	return true;
}
bool SequenceFieldNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> SequenceFieldNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}

	// TODO:  Needs sequence fields here


	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}

bool SequenceFieldNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
{
	//if (IsOptional())
	//{
	//	files->Header()->WriteLine("Asn1OptionalStruct _" + Name() + ";");
	//}
	//else
	{
		if (!!NameSpace())
			files->Header()->WriteLine(NameSpace()->ToString() + PODStructureName() + " _" + Name() + ";");
		else
			files->Header()->WriteLine(PODStructureName() + " _" + Name() + ";");
	}
	return true;
}
tsStringBase SequenceFieldNode::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (IsOptional())
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}
	else
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}

	return tmp;
}
tsStringBase SequenceFieldNode::BuildClearForMove(const tsStringBase& rightObject)
{
	return "";
}
bool SequenceFieldNode::WriteToJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	if (IsOptional())
	{
		file->WriteLine("if (_" + Name() + "_exists)");
		file->WriteLine("{");
		file->indent();
		file->WriteLine("obj.add(\"" + JSONName() + "\", _" + Name() + ".toJSON());");
		file->outdent();
		file->WriteLine("}");
	}
	else
	{
		file->WriteLine("obj.add(\"" + JSONName() + "\", _" + Name() + ".toJSON());");
	}

	return true;

}
bool SequenceFieldNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
		return true;

	if (IsOptional())
	{
		file->WriteLine("if (obj.hasField(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();
		file->WriteLine("if (!_" + Name() + "_exists)");
		file->WriteLine("    set_" + Name() + "();");
		file->WriteLine("if (!_" + Name() + ".fromJSON(obj.AsObject(\"" + JSONName() + "\")))");
		file->WriteLine("{");
		file->indent();
		file->WriteLine("return false;");
		file->outdent();
		file->WriteLine("}");
		file->outdent();
		file->WriteLine("}");
	}
	else
	{
		file->WriteLine("if (!_" + Name() + ".fromJSON(obj.AsObject(\"" + JSONName() + "\")))");
		file->WriteLine("    return false;");
	}

	return true;
}
void SequenceFieldNode::BuildInitializer(InitializerType type, tsStringBase& tmp)
{
	switch (type)
	{
	case ForCopy:
		if (!tmp.empty())
			tmp << ", ";
		tmp << "_" << Name() << "(obj._" << Name() << ")";
		break;
	case ForMove:
		if (!tmp.empty())
			tmp << ", ";
		tmp << "_" << Name() << "(std::move(obj._" << Name() << "))";
		break;
	default:
		break;
	}
}
bool SequenceFieldNode::WriteExportElement(std::shared_ptr<FileNode> files)
{
	tsStringBase line;

	line += "<Sequence";
	Attributes().foreach([&line](const char* name, const char* value) {
		line.append(" ").append(name).append("=\"").append(value).append("\"");
	});
	line += "/>";
	files->Export()->WriteLine(line);
	return true;
}
