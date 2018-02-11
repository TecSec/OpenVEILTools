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
#include "ChoiceFieldNode.h"
#include "DescriptionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceNode.h"
#include "SequenceFieldNode.h"
#include "SetNode.h"
#include "FileNode.h"

bool ChoiceFieldNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Choice is missing the Name attribute.\n");
		return false;
	}

	Name(Attributes().item("Name"));

	std::shared_ptr<Element> parentEle = GetParentElement();
	if (!Attributes().hasItem("ElementType") && !!parentEle)
	{
		if (parentEle->ElementType() == "Version" || parentEle->ElementType() == "SequencePart")
		{
			std::shared_ptr<Element> ele = ParentSequence()->FindElement(std::dynamic_pointer_cast<Element>(_me.lock()));

			if (!!ele)
			{
				Attributes().AddItem("ElementType", ele->BuildStructureName());
			}
		}
	}

	if (!Attributes().hasItem("ElementType"))
	{
		std::shared_ptr<tsXmlNode> co;
		std::shared_ptr<ChoiceNode> CO;
		tsAttributeMap map(Attributes());
		tsStringBase parentName = GetParentElement()->BuildStructureName();

		map.AddItem("Name", parentName + "_" + Attributes().item("Name"));
		//map.RemoveItem("Optional");
		if ((!!ParentSequence() && ParentSequence()->Export()) ||
		    (!!ParentSequenceOf() && ParentSequenceOf()->Export()) ||
		    (!!ParentChoice() && ParentChoice()->Export()))
			map.AddItem("Exported", "true");
		Attributes().AddItem("ElementType", map.item("Name"));

		if (!!ParentNamespace())
			co = ParentNamespace()->StartSubnode("Choice", map);
		else
			co = ParentFileNode()->StartSubnode("Choice", map);
		if (!co)
		{
			AddError("xml2Asn1CodeGen", "", "Choice is missing the ElementType attribute.\n");
			return false;
		}
		CO = std::dynamic_pointer_cast<ChoiceNode>(co);
		for (ptrdiff_t i = ChildrenCount() - 1; i >= 0; i--)
		{
			std::shared_ptr<tsXmlNode> child = ExtractChild(i);
			std::shared_ptr<FunctionNode> fn = std::dynamic_pointer_cast<FunctionNode>(child);
			co->Children().push_back(child);
			if (!!fn)
			{
				CO->Functions().push_back(fn);
			}
		}
		CO->ElementListForMove() = std::move(ElementListForMove());
		if (!std::dynamic_pointer_cast<ChoiceNode>(co)->Validate())
		{
			return false;
		}
	}


	std::shared_ptr<tsXmlNode> node = Parent().lock();

	while (!!node && !std::dynamic_pointer_cast<Element>(node))
		node = node->Parent().lock();

	if (!node)
	{
		AddError("xml2Asn1CodeGen", "", "Unable to find the node container for this choice.\n");
		return false;
	}
	Element::StructureName(Attributes().item("ElementType"));
	//	StructureName(std::dynamic_pointer_cast<Element>(node)->NameForParent() + "_" + Name());
	JSONName(Attributes().item("JSONName"));
	CppType(StructureName());
	IsOptional(Attributes().itemAsBoolean("Optional", false));

	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node1 = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node1);
		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}

	if (!!ParentSequence())
		_element = std::dynamic_pointer_cast<ChoiceNode>(ParentSequence()->FindElement(std::dynamic_pointer_cast<Element>(_me.lock())));
	if (!_element)
	{
		_element = FindChoice(Attributes().item("ElementType"));
		if (!!_element)
		{
			if (!!ParentSequence())
			{
				ParentSequence()->AddDependency(_element);
			}
			else if (!!ParentSequenceOf())
			{
				ParentSequenceOf()->AddDependency(_element);
			}
			else if (!!ParentChoice())
			{
				ParentChoice()->AddDependency(_element);
			}
			_namespace = _element->NameSpace();
		}
	}

	if (!_element)
	{
		AddError("xml2Asn1CodeGen", "", "Choice:ElementType does not refer to a Choice element:  " + Attributes().item("ElementType"));
		return false;
	}

	if (StructureName().size() == 0)
	{
		AddError("xml2Asn1CodeGen", "", "A choice field must specify either a list of fields or an ElementType (not both).\n");
		return false;
	}

	return true;
}
bool ChoiceFieldNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> ChoiceFieldNode::CreateNode(const tsStringBase &name, const tsAttributeMap &map)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else  if (name == "Function" && !Attributes().hasItem("ElementType"))
	{
		tmp = IObject::Create<FunctionNode>();
	}
	else if (!Attributes().hasItem("ElementType"))
	{
		tmp = SequenceNode::BuildField(std::dynamic_pointer_cast<ElementContainer>(_me.lock()), name, map, GetFileNode());
	}

	if (!!tmp)
	{
		tmp->Attributes() = map;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}

bool ChoiceFieldNode::WriteForwardReference(std::shared_ptr<FileNode> files)
{
	if (!ContainedInArray())
	{
		if (!MatchingElement())
		{
			if (!ParentSequence())
			{
				AddError("xml2Asn1CodeGen", "", tsStringBase().append("Element ").append(StructureName()).append(" has no valid parent element.\n"));
			}
			else
				AddError("xml2Asn1CodeGen", "", tsStringBase().append("Structure ").append(ParentSequence()->StructureName()).append(" does not contain the element called ").append(Name()).append("."));
			return false;
		}
	}

	UNREFERENCED_PARAMETER(files);
	//files->Header()->SetNamespace(NameSpace());
	//files->Header()->WriteLine("struct " + files->ExportSymbol() + StructureName() + ";");
	return true;
}
bool ChoiceFieldNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
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
bool ChoiceFieldNode::WritePODStructure(std::shared_ptr<FileNode> files)
{
	UNREFERENCED_PARAMETER(files);

	if (PODStructureWritten())
		return true;
	PODStructureWritten(true);

	//SequenceNode* parent = dynamic_cast<SequenceNode*>(this->Parent());

	//if (parent != nullptr)
	//{
	//	if (!parent->WriteFieldMetadata(files->Source(), nullptr, "", "", 0))
	//		return false;
	//}

	if (StructureName().size() == 0)
	{
		if (!MatchingElement())
		{
			AddError("xml2Asn1CodeGen", "", "The matching choice element is missing in the parent sequence.");
			return false;
		}
		if (!MatchingElement()->WritePODStructure(files))
			return false;
	}

	return true;
}
bool ChoiceFieldNode::WriteStructure(std::shared_ptr<FileNode> files)
{
	UNREFERENCED_PARAMETER(files);

	if (StructureWritten())
		return true;
	StructureWritten(true);

	//SequenceNode* parent = dynamic_cast<SequenceNode*>(this->Parent());

	//if (parent != nullptr)
	//{
	//	if (!parent->WriteFieldMetadata(files->Source(), nullptr, "", "", 0))
	//		return false;
	//}

	if (StructureName().size() == 0)
	{
		if (!MatchingElement())
		{
			AddError("xml2Asn1CodeGen", "", "The matching choice element is missing in the parent sequence.");
			return false;
		}
		if (!MatchingElement()->WriteStructure(files))
			return false;
	}

	return true;
}
tsStringBase ChoiceFieldNode::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (IsOptional())
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}
	else
	{
		tmp.append("_" ).append(Name() ).append(" = std::move(" ).append(rightObject ).append("_" ).append(Name() ).append(");");
	}

	return tmp;
}
tsStringBase ChoiceFieldNode::BuildClearForMove(const tsStringBase& rightObject)
{
	return "";
}

bool ChoiceFieldNode::WriteToJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("#error  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	if (IsOptional())
	{
		file->WriteLine("if (_" + Name() + "_exists)");
		file->WriteLine("{");
		file->indent();
	}

	file->WriteLine("obj.add(\"" + JSONName() + "\", _" + Name() + ".toJSON());");

	if (IsOptional())
	{
		file->outdent();
		file->WriteLine("}");
	}

	return true;
}
bool ChoiceFieldNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
		return true;

	if (IsOptional())
	{
		file->WriteLine("if (obj.hasField(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();
	}

	file->WriteLine("if (!_" + Name() + ".fromJSON(obj.AsObject(\"" + JSONName() + "\")))");
	file->WriteLine("    return false;");

	if (IsOptional())
	{
		file->outdent();
		file->WriteLine("}");
	}

	return true;
}
tsStringBase ChoiceFieldNode::LocalStructureName()
{
	if (StructureName().size() > 0)
		return StructureName();
	if (_localStructureName.size() == 0)
	{
		_localStructureName.append(FullStructureName()).append("_").append(std::dynamic_pointer_cast<Element>(ParentContainer())->ElementType()).append("_").append(std::dynamic_pointer_cast<Element>(ParentContainer())->Name());
	}
	return _localStructureName;
}

bool ChoiceFieldNode::WriteExportElement(std::shared_ptr<FileNode> files)
{
	tsStringBase line;

	line += "<Choice";
	Attributes().foreach([&line](const char* name, const char* value) {
		line.append(" ").append(name).append("=\"").append(value).append("\"");
	});
	line += "/>";
	files->Export()->WriteLine(line);
	return true;
}
void ChoiceFieldNode::BuildInitializer(InitializerType type, tsStringBase& tmp)
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
		return;
	}
}