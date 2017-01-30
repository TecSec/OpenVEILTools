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
#include "SequenceOfFieldNode.h"
#include "DescriptionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceNode.h"
#include "SequenceFieldNode.h"
#include "SetNode.h"
#include "FileNode.h"
#include "VersionNode.h"
#include "PartNode.h"

bool SequenceOfFieldNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "SequenceOf is missing the Name attribute.\n");
		return false;
	}
	Name(Attributes().item("Name"));

	std::shared_ptr<ElementContainer> parentCont = ParentContainer();
	std::shared_ptr<VersionNode> vn = std::dynamic_pointer_cast<VersionNode>(Parent().lock());

	if (!Attributes().hasItem("ElementType") && (!!parentCont || !!vn))
	{
		if (!!vn || !!std::dynamic_pointer_cast<PartNode>(parentCont))
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
		std::shared_ptr<tsXmlNode> so;
		std::shared_ptr<SequenceOfNode> SO;
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
			so = ParentNamespace()->StartSubnode("SequenceOf", map);
		else
			so = ParentFileNode()->StartSubnode("SequenceOf", map);
		if (!so)
		{
			AddError("xml2Asn1CodeGen", "", "SequenceOf is missing the ElementType attribute.\n");
			return false;
		}
		SO = std::dynamic_pointer_cast<SequenceOfNode>(so);
		for (ptrdiff_t i = ChildrenCount() - 1; i >= 0; i--)
		{
			std::shared_ptr<tsXmlNode> child = ExtractChild(i);
			std::shared_ptr<FunctionNode> fn = std::dynamic_pointer_cast<FunctionNode>(child);
			so->Children().push_back(child);
			if (!!fn)
			{
				SO->Functions().push_back(fn);
			}
		}
		SO->ElementListForMove() = std::move(ElementListForMove());
		if (!std::dynamic_pointer_cast<SequenceOfNode>(so)->Validate())
		{
			return false;
		}
	}
	StructureName(Attributes().item("ElementType"));
	Tag(Attributes().item("Tag"));
	Type(Attributes().item("Type"));

	ElementName(Parent().lock()->Attributes().item("Name") + "_" + Name());
	JSONName(Attributes().item("JSONName"));
	IsOptional(Attributes().itemAsBoolean("Optional", false));


	//if (!!ParentSequence())
	//	_element = std::dynamic_pointer_cast<SequenceOfNode>(ParentSequence()->FindElement(std::dynamic_pointer_cast<Element>(_me.lock())));
	//if (!_element)
	//{
		_element = FindSequenceOf(/*Attributes().item("ElementType").split(":")->back()*/ StructureName());
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
	//}

	if (!_element)
	{
		AddError("xml2Asn1CodeGen", "", "SequenceOf:ElementType does not refer to a SequenceOf element:  " + Attributes().item("ElementType"));
		return false;
	}

	//if (!_element->Validate())
	//	return false;

	if (Tag() == "-1")
	{
		Tag(_element->Tag());
		Type(_element->Type());
	}

	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}

	ElementName(_element->ElementName());

	StructureName(_element->StructureName());

	CppType(_element->StructureName());
	return true;
}
bool SequenceOfFieldNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> SequenceOfFieldNode::CreateNode(const tsStringBase &name, const tsAttributeMap &map)
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

bool SequenceOfFieldNode::IsArray()
{
	return false;
}
tsStringBase SequenceOfFieldNode::GetArrayStructureName()
{
	return _element->GetArrayStructureName();
}
tsStringBase SequenceOfFieldNode::GetArrayElementStructureName()
{
	return ElementName();
}
bool SequenceOfFieldNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
{
//	if (IsOptional())
//	{
//
//		files->Header()->WriteLine("Asn1OptionalStruct _" + Name() + ";");
////		files->Header()->WriteLine("Asn1OptionalField<" + StructureName() + " > _" + Name() + ";");
//	}
//	else
	{
		if (!!_element && !!_element->NameSpace())
			files->Header()->WriteLine(_element->NameSpace()->ToString() + PODStructureName() + " _" + Name() + ";");
		else
			files->Header()->WriteLine(PODStructureName() + " _" + Name() + ";");
	}
	return true;
}
tsStringBase SequenceOfFieldNode::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	//if (IsOptional())
	//{
	//	tmp << "_" << Name() << " = std::move(" << rightObject << "_" << Name() << ");";
	//}
	//else
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}

	return tmp;
}
tsStringBase SequenceOfFieldNode::BuildClearForMove(const tsStringBase& rightObject)
{
	return "";
}
tsStringBase SequenceOfFieldNode::BuildCopyLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		tmp += "// Null fields skipped";
	}
	else
	{
		//if (!IsOptional())
		//{
		//	tmp << "_" << Name() << " = " << rightObject << "_" << Name() << "->cloneContainer();";
		//}
		//else
		{
			tmp.append("_").append(Name()).append(" = ").append(rightObject).append("_").append(Name()).append(";");
		}
	}
	return tmp;
}
tsStringBase SequenceOfFieldNode::BuildCloneLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		tmp += "// Null fields skipped";
	}
	else
	{
		//if (!IsOptional())
		//{
		//	tmp << rightObject << "_" << Name() << " = " << "_" << Name() << "->cloneContainer();";
		//}
		//else
		{
			tmp .append(rightObject).append("_").append(Name()).append(" = ").append("_").append(Name()).append(";");
		}
	}
	return tmp;
}
bool SequenceOfFieldNode::WriteToJSON(File* file)
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
		file->WriteLine("if (!_" + Name() + ".toJSON(obj))");
		file->WriteLine("	return false;");
		file->outdent();
		file->WriteLine("}");
	}
	else
	{
		file->WriteLine("if (!_" + Name() + ".toJSON(obj))");
		file->WriteLine("	return false;");
	}
	return true;
}
//bool SequenceOfFieldNode::WriteToJSON(File* file, const tsCryptoString& fieldName, const tsCryptoString& containerName)
//{
//	file->WriteLine("#error SequenceOfFieldNode::WriteToJSON");
//	//if (IsOptional())
//	//{
//	//	file->WriteLine("if (_" + containerName + ".exists)");
//	//	file->WriteLine("{");
//	//	file->indent();
//	//}
//
//	//std::shared_ptr<SequenceFieldNode> sequence = std::dynamic_pointer_cast<SequenceFieldNode>(Elements()[0]);
//
//	//if (!!sequence)
//	//{
//	//	file->WriteLine("obj.createArrayField(\"" + fieldName + "\");");
//	//	file->WriteLine("std::for_each(_" + containerName + ".value->begin(), _" + containerName + ".value->end(), [&obj](const std::shared_ptr<Asn1DataBaseClass>& o){");
//	//	file->WriteLine("    std::shared_ptr<" + ElementName() + "> data = std::dynamic_pointer_cast<" + ElementName() + ">(o);");
//	//	file->WriteLine("    obj.add(\"" + fieldName + "\", data->toJSON());");
//	//	file->WriteLine("});");
//	//}
//	//else
//	//	file->WriteLine(" // NOTE:  Implement me - Array - WriteToJSON");
//
//	//if (IsOptional())
//	//{
//	//	file->outdent();
//	//	file->WriteLine("}");
//	//}
//	return true;
//}
bool SequenceOfFieldNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	if (IsOptional())
	{
		file->WriteLine("if (obj.hasField(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();
		file->WriteLine("if (!_" + Name() + "_exists)");
		file->WriteLine("	_" + Name() + "_exists = true;");
		file->WriteLine("_" + Name() + ".fromJSON(obj);");
		file->outdent();
		file->WriteLine("}");
	}
	else
	{
		file->WriteLine("_" + Name() + ".fromJSON(obj);");
	}
	return true;

}
//bool SequenceOfFieldNode::WriteFromJSON(File* file, const tsCryptoString& fieldName, const tsCryptoString& containerName)
//{
//	file->WriteLine("#error SequenceOfFieldNode::WriteFromJSON");
//	//if (IsOptional())
//	//{
//	//	file->WriteLine("if (obj.hasField(\"" + fieldName + "\"))");
//	//	file->WriteLine("{");
//	//	file->indent();
//	//}
//	//std::shared_ptr<SequenceFieldNode> sequence = std::dynamic_pointer_cast<SequenceFieldNode>(Elements()[0]);
//
//	//if (!!sequence)
//	//{
//	//	file->WriteLine("obj.foreach(\"" + fieldName + "\", [this](const JSONField&fld){");
//	//	file->WriteLine("");
//	//	file->WriteLine("	if (fld.Type() == JSONField::jsonObject)");
//	//	file->WriteLine("	{");
//	//	file->WriteLine("		" + ElementName() + " data;");
//	//	file->WriteLine("");
//	//	file->WriteLine("		if (data.fromJSON(fld.AsObject()))");
//	//	if (IsOptional())
//	//	{
//	//		file->WriteLine("			this->_" + containerName + ".add(std::move(data));");
//	//	}
//	//	else
//	//	{
//	//		file->WriteLine("			this->_" + Name() + "->push_back(std::shared_ptr<Asn1DataBaseClass>(data.clone()));");
//	//	}
//	//	file->WriteLine("	}");
//	//	file->WriteLine("});");
//	//}
//	//else
//	//	file->WriteLine(" // NOTE:  Implement me - Array - WriteFromJSON");
//
//	//if (IsOptional())
//	//{
//	//	file->outdent();
//	//	file->WriteLine("}");
//	//}
//	return true;
//}

tsStringBase SequenceOfFieldNode::BuildMetadataLine(const tsStringBase& structureName, const tsStringBase& PODstructureName)
{
	tsStringBase origName(_element->Name());
	tsStringBase origTag(_element->Tag());
	tsStringBase origType(_element->Type());
	bool origOptional(_element->IsOptional());
	_element->Name(Name());
	_element->Tag(Tag());
	_element->Type(Type());
	_element->IsOptional(IsOptional());

	tsStringBase tmp = _element->BuildMetadataLine(structureName, PODstructureName);

	_element->IsOptional(origOptional);
	_element->Name(origName);
	_element->Tag(origTag);
	_element->Type(origType);
	return tmp;
}
void SequenceOfFieldNode::BuildInitializer(InitializerType type, tsStringBase& tmp)
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

bool SequenceOfFieldNode::WriteExportElement(std::shared_ptr<FileNode> files)
{
	tsStringBase line;

	line += "<SequenceOf";
	Attributes().foreach([&line](const __tsAttributeMapItem& item) {
		line.append(" ").append(item.m_name).append("=\"").append(item.m_value).append("\"");
	});
	line += "/>";
	files->Export()->WriteLine(line);
	return true;
}
