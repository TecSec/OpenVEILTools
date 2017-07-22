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
#include "BasicFieldNode.h"
#include "DescriptionNode.h"
#include "FileNode.h"

bool BasicFieldNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "BasicField is missing the Name attribute.\n");
		return false;
	}

	// Convert enums into the underlying base type
	if (CppType() == "enum")
	{
		CppType(Attributes().item("ElementType"));
		if (CppType().size() == 0)
			CppType(Attributes().item("BaseType"));
		if (CppType().size() == 0)
			CppType("int32_t");

		auto it = std::find_if(Element::UserDefinedBasicTypes().begin(), Element::UserDefinedBasicTypes().end(), [this](tsStringBase& val) { return val == CppType(); });
		if (it == Element::UserDefinedBasicTypes().end())
			Element::UserDefinedBasicTypes().push_back(CppType());
	}
	// Convert NamedInts into the underlying base type
	else if (CppType() == "NamedInt")
	{
		std::shared_ptr<NamedInt> ni = this->FindNamedInt(Attributes().item("ElementType"));

		if (!!ni)
		{
			CppType(ni->FullName());
		}
		if (CppType().size() == 0)
			CppType(Attributes().item("BaseType"));
		if (CppType().size() == 0)
			CppType("int32_t");

		auto it = std::find_if(Element::UserDefinedBasicTypes().begin(), Element::UserDefinedBasicTypes().end(), [this](tsStringBase& val) { return val == CppType(); });
		if (it == Element::UserDefinedBasicTypes().end())
			Element::UserDefinedBasicTypes().push_back(CppType());
	}

	Default(Attributes().item("Default"));
	if (Attributes().hasItem("Initializer"))
		Initializer(Attributes().item("Initializer"));
	if (Initializer().size() == 0)
	{
		if (Default().size() > 0)
			Initializer(Default());
		else if (isBasicType(CppType()))
		{
			Initializer("0");
		}
	}

	Name(Attributes().item("Name"));
	Type(Attributes().item("Type"));
	//if (Type().size() == 0)
	//	Type("Universal");

	Tag(Attributes().item("Tag"));
	//if (Tag().size() == 0)
	//	Tag(DefaultTag(std::dynamic_pointer_cast<tsXmlNode>(_me.lock())));

	ElementType(NodeName());
	JSONName(Attributes().item("JSONName"));

	IsOptional(Attributes().itemAsBoolean("Optional", false));

	if (getCanEncode(ElementType()))
	{
		EncodedType(Attributes().item("EncodedType"));
		EncodedAccessor(Attributes().item("EncodedAccessor"));
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
	return true;
}
bool BasicFieldNode::WriteExportElement(std::shared_ptr<FileNode> files)
{
	tsStringBase line;

	line.append("<").append(ElementType());
	Attributes().foreach([&line](const __tsAttributeMapItem& item) {
		line.append(" ").append(item.m_name).append("=\"").append(item.m_value).append("\"");
	});
	line += "/>";
	files->Export()->WriteLine(line);
	return true;
}
bool BasicFieldNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> BasicFieldNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
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

bool BasicFieldNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
{
	/*if (IsOptional())
	{
		tsCryptoString tmp = getOptionalType(ElementType());

		if (tmp.size() == 0)
		{
			return false;
		}
		files->Header()->WriteLine(tmp + " _" + Name() + ";");
	}
	else*/ if (ElementType() == "Null")
	{

	}
    else if (gAsC)
    {
        files->Header()->WriteLine(C_Type() + " _" + Name() + ";");
    }
	else
	{
		files->Header()->WriteLine(CppType() + " _" + Name() + ";");
	}
return true;
}
tsStringBase BasicFieldNode::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		return "// Null fields have nothing to move";
	}
	if (IsOptional())
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}
	else
	{
		if (isBasicType(CppType()))
		{
			return Element::BuildMoveLine(rightObject);
		}
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}
	return tmp;
}
tsStringBase BasicFieldNode::BuildClearForMove(const tsStringBase& rightObject)
{
	if (ElementType() == "Null")
	{
		return "";
	}
	if (IsOptional())
	{
	}
	else
	{
		if (isBasicType(CppType()))
		{
			return Element::BuildClearForMove(rightObject);
		}
	}
	return "";
}

bool BasicFieldNode::WriteToJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  JSON name not set for field _" + Name());
		return true;
	}

	if (IsOptional())
	{
		file->WriteLine("if (_" + Name() + "_exists)");
		file->WriteLine("{");
		file->indent();

		tsStringBase type = ElementType();
		tsStringBase tmp;

		tmp = getToOptionalJsonLine(type);
		if (type == "Any")
		{

			file->WriteLine("if (tscrypto::gPersistAnyfieldAsObject)");
			file->WriteLine("{");
			file->indent();
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()));
			file->outdent();
			file->WriteLine("}");
			file->WriteLine("else");
			file->WriteLine("{");
			file->indent();
			file->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
			file->WriteLine("std::shared_ptr<tscrypto::TlvNode> node = doc->CreateTlvNode(_" + Name() + ".tag, (uint8_t)_" + Name() + ".type);");
			file->WriteLine("node->InnerData(_" + Name() + ".value);");
			file->WriteLine("obj.add(\"" + JSONName() + "\", node->OuterData().ToBase64());");
			file->outdent();
			file->WriteLine("}");
		}
		else if (tmp.size() > 0)
		{
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()));
		}
		else
		{
			file->WriteLine("#error:  Missing optional support for " + JSONName() + " on field _" + Name());
		}

		file->outdent();
		file->WriteLine("}");
	}
	else
	{
		tsStringBase type = ElementType();
		tsStringBase tmp;

		tmp = getToJsonLine(type);
		if (type == "Any")
		{
			file->WriteLine("if (tscrypto::gPersistAnyfieldAsObject)");
			file->WriteLine("{");
			file->indent();
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()));
			file->outdent();
			file->WriteLine("}");
			file->WriteLine("else");
			file->WriteLine("{");
			file->indent();

			file->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
			file->WriteLine("std::shared_ptr<tscrypto::TlvNode> node = doc->CreateTlvNode(_" + Name() + ".tag, (uint8_t)_" + Name() + ".type);");
			file->WriteLine("node->InnerData(_" + Name() + ".value);");
			file->WriteLine("obj.add(\"" + JSONName() + "\", node->OuterData().ToBase64());");

			file->outdent();
			file->WriteLine("}");
		}
		else if (tmp.size() > 0)
		{
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()));
		}
		else if (type == "Null")
		{
		}
		else
		{
			file->WriteLine("#error  Missing optional support for " + JSONName() + " on field _" + Name());
			return false;
		}
	}

	return true;
}
bool BasicFieldNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
		return true;

	if (IsOptional())
	{
		file->WriteLine("if (obj.hasField(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();

		tsStringBase type = ElementType();
		tsStringBase tmp;

		tmp = getFromJsonLine(type);
		file->WriteLine("_" + Name() + "_exists = true;");

		if (type == "Any")
		{
			file->WriteLine("if (obj.field(\"" + JSONName() + "\").Type() == tscrypto::JSONField::jsonString)");
			file->WriteLine("{");
			file->WriteLine("    std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
			file->WriteLine("");
			file->WriteLine("    if (!doc->LoadTlv(obj.AsString(\"" + JSONName() + "\").Base64ToData()))");
			file->WriteLine("        return false;");
			file->WriteLine("    _" + Name() + ".tag = doc->DocumentElement()->Tag();");
			file->WriteLine("    _" + Name() + ".type = doc->DocumentElement()->Type();");
			file->WriteLine("    _" + Name() + ".value = doc->DocumentElement()->InnerData();");
			file->WriteLine("}");
			file->WriteLine("else");
			file->WriteLine("{");
			tmp.insert(0, "    ");
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()).Replace("{CppType}", CppType()).Replace("{Initializer}", Initializer()));
			file->WriteLine("}");
		}
		else if (tmp.size() > 0)
		{
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()).Replace("{CppType}", CppType()).Replace("{Initializer}", Initializer()));
		}
		else
		{
			return false;
		}

		file->outdent();
		file->WriteLine("}");
		return true;
	}
	else
	{
		// _FiefdomOID = ToGuid()(obj.AsString("fiefdomid"));
		tsStringBase type = ElementType();
		tsStringBase tmp;

		tmp = getFromJsonLine(type);
		if (type == "Any")
		{
			file->WriteLine("if (obj.field(\"" + JSONName() + "\").Type() == tscrypto::JSONField::jsonString)");
			file->WriteLine("{");
			file->WriteLine("    std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
			file->WriteLine("");
			file->WriteLine("    if (!doc->LoadTlv(obj.AsString(\"" + JSONName() + "\").Base64ToData()))");
			file->WriteLine("        return false;");
			file->WriteLine("    _" + Name() + ".tag = doc->DocumentElement()->Tag();");
			file->WriteLine("    _" + Name() + ".type = doc->DocumentElement()->Type();");
			file->WriteLine("    _" + Name() + ".value = doc->DocumentElement()->InnerData();");
			file->WriteLine("}");
			file->WriteLine("else");
			file->WriteLine("{");
			tmp.insert(0, "    ");
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()).Replace("{CppType}", CppType()).Replace("{Initializer}", Initializer()));
			file->WriteLine("}");
		}
		else if (tmp.size() > 0)
		{
			file->WriteLine(tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", Name()).Replace("{CppType}", CppType()).Replace("{Initializer}", Initializer()));
		}
		else if (type == "Null")
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}
void BasicFieldNode::BuildInitializer(InitializerType type, tsStringBase& tmp)
{
	if (ElementType() == "Null")
		return;

	if (isBasicType(CppType()))
	{
		if (tmp.size() != 0)
			tmp += ", ";

		switch (type)
		{
		case ForConstruct:
			tmp += tsStringBase(getClassInitializer(ElementType())).Replace("{Name}", Name()).Replace("{Initializer}", Initializer());
			break;
		case ForCopy:
			tmp += "_" + Name() + "(obj._" + Name() + ")";
			break;
		case ForMove:
			tmp += "_" + Name() + "(std::move(obj._" + Name() + "))";
			break;
		}
	}
	else
	{
		switch (type)
		{
		case ForConstruct:
			break;
		case ForCopy:
			if (tmp.size() != 0)
				tmp += ", ";
			tmp += "_" + Name() + "(obj._" + Name() + ")";
			break;
		case ForMove:
			if (tmp.size() != 0)
				tmp += ", ";
			tmp += "_" + Name() + "(std::move(obj._" + Name() + "))";
			break;
		}
	}
}