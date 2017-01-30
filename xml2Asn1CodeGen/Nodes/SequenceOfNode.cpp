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
#include "SetNode.h"
#include "DescriptionNode.h"
#include "FunctionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceNode.h"
#include "ChoiceFieldNode.h"
#include "SequenceFieldNode.h"
#include "SetNode.h"
#include "FileNode.h"
#include "SequenceOfNode.h"
#include "SequenceOfFieldNode.h"

bool SequenceOfNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	tsStringBase tmp;

	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "SequenceOf is missing the Name attribute.\n");
		return false;
	}
	Name(Attributes().item("Name"));
	Tag(Attributes().item("Tag"));
	Type(Attributes().item("Type"));

	Export(Attributes().itemAsBoolean("Exported", false));
	Import(Attributes().itemAsBoolean("Imported", false));
	JSONName(Attributes().item("JSONName"));
	IsOptional(Attributes().itemAsBoolean("Optional", false));

	if (!!ParentContainer() && !std::dynamic_pointer_cast<FileNode>(ParentContainer()))
	{
		StructureName(ParentContainer()->StructureName() + "_" + Attributes().item("Name"));

	}
	else
	{
		StructureName(Attributes().item("Name"));
	}
	if (!Import())
	{
		if (_fields.size() == 0)
		{
			AddError("xml2Asn1CodeGen", "", "SequenceOf must contain one element.\n");
			return false;
		}
		if (_fields.size() > 1)
		{
			// TODO:  Combine fields into a struct???
			AddError("xml2Asn1CodeGen", "", "SequenceOf may only contain one element.\n");
			return false;
		}
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

	if (!Import())
	{
		std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(_fields[0]);

		if (!ele)
		{
			AddError("xml2Asn1CodeGen", "", "The SequenceOf element is not of the proper type.\n");
			return false;
		}

		AddDependency(ele);

		//if (IsOptional())
		//{
		//	tsCryptoString type = ele->ElementType();
		//	tsCryptoString nonOptArrayType;

		//	_arrayType = getOptionalArrayType(type);
		//	if (_arrayType.size() == 0)
		//	{
		//		throw std::runtime_error("Invalid or unsupported optional SequenceOf type.");
		//	}


		//	if (ele->StructureName().size() > 0)
		//	{
		//		ElementName(ele->StructureName());
		//		//_arrayType << StructureName();
		//		nonOptArrayType = "Asn1DataBaseClassList";
		//	}
		//	else
		//	{
		//		ElementName(ele->CppType());

		//		nonOptArrayType << ElementName();
		//		nonOptArrayType.Replace("_t", "");
		//		nonOptArrayType << "List";
		//	}
		//	tmp = nonOptArrayType;
		//	tmp[0] = toupper(tmp[0]);
		//	_arrayCreateType << "Create" << tmp;
		//}
		//else
		{
			if (ele->StructureName().size() > 0)
			{
				ElementName(ele->StructureName());
				//if (!!ele->NameSpace())
				//	_arrayType = "standardLayoutList<" + ele->NameSpace()->ToString() + ele->PODStructureName() + ">";
				//else
				//	_arrayType = "standardLayoutList<" + ele->PODStructureName() + ">";
				_arrayType = "tscrypto::standardLayoutList<tscrypto::Asn1ObjectWrapper>";
			}
			else
			{
				ElementName(ele->CppType());

				//tmp.append(ElementName());
				//tmp.Replace("_t", "");
				//tmp += "List";
				//if (tmp.find("::") == tsCryptoString::npos)
				//	tmp.insert(0, "");
				_arrayType = "tscrypto::standardLayoutList<" + ele->CppType() + ">";
			}


			//tsCryptoStringList parts = _arrayType.split("::");
			//tsCryptoString tmp1;
			//if (parts->size() > 1)
			//{
			//	for (size_t i = 0; i < parts->size() - 1; i++)
			//	{
			//		tmp1 << parts->at(i) << "::";
			//	}
			//}

			//tmp1 << "Create";
			//tmp = parts->at(parts->size() - 1);
			//tmp[0] = toupper(tmp[0]);
			//tmp.prepend(tmp1);
			//_arrayCreateType = tmp;
		}

		//CppType(StructureName());
		//ElementType(StructureName());
		ele->ContainedInArray(true);
	}


	return true;
}
bool SequenceOfNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> SequenceOfNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else  if (name == "Function")
	{
		tmp = IObject::Create<FunctionNode>();
		Functions().push_back(std::dynamic_pointer_cast<FunctionNode>(tmp));
	}
	else
	{
		tmp = SequenceNode::BuildField(std::dynamic_pointer_cast<ElementContainer>(_me.lock()), name, Attributes, GetFileNode());
	}

	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}

bool SequenceOfNode::WriteForwardReference(std::shared_ptr<FileNode> files)
{
	if (!ForwardsWritten())
	{
		ForwardsWritten(true);

		for (auto& ele : Dependencies())
		{
			if (!ele->WriteForwardReference(files))
				return false;
		}

		if (!Import())
		{
			files->Header()->SetNamespace(NameSpace());
			files->Header()->WriteLine("struct " + PODStructureName() + ";");
			if (Export())
			{
				tsStringBase line;

				files->Export()->SetNamespace(NameSpace());
				line.append("<SequenceOf Name=\"").append(StructureName()).append("\" Imported=\"true\"");
				if (Tag().size() > 0)
					line.append(" Tag=\"").append(Tag()).append("\"");
				if (Type().size() > 0)
					line.append(" Tag=\"").append(Type()).append("\"");
				files->Export()->WriteLine(line + "/>");
			}
		}
	}
	return true;
}
bool SequenceOfNode::IsArray()
{
	return false;
}
tsStringBase SequenceOfNode::GetArrayStructureName()
{
	if (Elements().size() > 0 && !!Elements()[0])
		return Elements()[0]->StructureName();
	return "";
}
tsStringBase SequenceOfNode::GetArrayElementStructureName()
{
	return ElementName();
}
bool SequenceOfNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
{
	if (!!NameSpace())
		files->Header()->WriteLine(NameSpace()->ToString() + PODStructureName() + " _" + Name() + ";");
	else
		files->Header()->WriteLine(PODStructureName() + " _" + Name() + ";");
	return true;
}
void SequenceOfNode::BuildSequenceOfInitializer(tsStringBase& tmp)
{
	//if (!IsOptional())
	//{
	//	tsCryptoString name = getListCreator(Elements()[0]->ElementType());

	//	if (tmp.size() != 0)
	//		tmp.append(", ");

	//	tmp.append("_list(").append(name).append("())");
	//}
}
tsStringBase SequenceOfNode::buildInitializers(InitializerType type)
{
	tsStringBase tmp;

	BuildSequenceOfInitializer(tmp);

	if (tmp.size() > 0)
		tmp.prepend(" : ");
	return tmp;
}
tsStringBase SequenceOfNode::BuildMoveLine(const tsStringBase& rightObject)
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
tsStringBase SequenceOfNode::BuildClearForMove(const tsStringBase& rightObject)
{
	return "";
}
tsStringBase SequenceOfNode::BuildCopyLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		tmp.append("// Null fields skipped");
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
tsStringBase SequenceOfNode::BuildCloneLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		tmp.append("// Null fields skipped");
	}
	else
	{
		//if (!IsOptional())
		//{
		//	tmp << rightObject << "_" << Name() << " = " << "_" << Name() << "->cloneContainer();";
		//}
		//else
		{
			tmp.append(rightObject).append("_").append(Name()).append(" = ").append("_").append(Name()).append(";");
		}
	}
	return tmp;
}

bool SequenceOfNode::WriteToJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	tsStringBase type = Elements()[0]->ElementType();
	tsStringBase tmp;
	tsStringBase eleNS;
	tsStringBase POD;
	
	if (!!Elements()[0]->NameSpace())
		eleNS = Elements()[0]->NameSpace()->ToString();

	POD = eleNS + Elements()[0]->PODStructureName();

	//if (IsOptional())
	//{
	//	file->WriteLine("if (_list.exists)");
	//	file->WriteLine("{");
	//	file->indent();
	//}
	tmp = getToJsonLine(type);

	if (tmp.size() > 0)
	{
		tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", "list[i]").Replace("{struct}", POD);
	}
	else
	{
		file->WriteLine("#error  Missing optional support for " + Elements()[0]->JSONName() + " on field _" + Elements()[0]->Name());
		return false;
	}

	file->WriteLine("if (!obj.hasField(\"" + JSONName() + "\"))");
	file->WriteLine("	obj.createArrayField(\"" + JSONName() + "\");");

	//if (IsOptional())
	//	file->WriteLine(tsCryptoString() << "for (const " << getListIteratorType(type) << "& _o : *_list.value)");
	//else
	file->WriteLine(tsStringBase().append("for (size_t i = 0; i < _list.size(); i++)"));
	file->WriteLine("{");
	file->indent();
	file->WriteLine(tmp);
	file->outdent();
	file->WriteLine("}");

	//if (IsOptional())
	//{
	//	file->outdent();
	//	file->WriteLine("}");
	//}

	return true;
}
bool SequenceOfNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	tsStringBase eleNS;
	tsStringBase POD;

	if (!!Elements()[0]->NameSpace())
		eleNS = Elements()[0]->NameSpace()->ToString();

	POD = eleNS + Elements()[0]->PODStructureName();

	//if (IsOptional())
	//{
	//	file->WriteLine("if (obj.hasField(\"" + JSONName() + "\") && obj.field(\"" + JSONName() + "\").Type() == JSONField::jsonArray)");
	//	file->WriteLine("{");
	//	file->indent();
	//	file->WriteLine("_list.exists = true;");
	//}

	std::shared_ptr<SequenceFieldNode> sequence = std::dynamic_pointer_cast<SequenceFieldNode>(Elements()[0]);
	std::shared_ptr<ChoiceFieldNode> choice = std::dynamic_pointer_cast<ChoiceFieldNode>(Elements()[0]);
	std::shared_ptr<SequenceOfFieldNode> seqOf = std::dynamic_pointer_cast<SequenceOfFieldNode>(Elements()[0]);

	if (!!sequence || !!choice || !!seqOf)
	{
		file->WriteLine("obj.foreach(\"" + JSONName() + "\", [this](const tscrypto::JSONField&fld){");
		file->WriteLine("");
		file->WriteLine("	if (fld.Type() == tscrypto::JSONField::jsonObject)");
		file->WriteLine("	{");
		file->WriteLine("		" + POD + " data;");
		file->WriteLine("");
		file->WriteLine("		if (data.fromJSON(fld.AsObject()))");
		//if (IsOptional())
		//{
		//	file->WriteLine("			this->_list.add(std::move(data));");
		//}
		//else
		{
			file->WriteLine("			this->add(data);");
		}
		file->WriteLine("	}");
		file->WriteLine("});");
	}
	else
	{
		file->WriteLine("for (auto& fld : *obj.AsArray(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();
		file->WriteLine(Elements()[0]->CppType() + " tmp;");
		tsStringBase tmp;

		tmp = getFromJsonLineForArray(Elements()[0]->ElementType());
		if (tmp.size() > 0)
		{
			file->WriteLine(tmp);
		}
		else
		{
			return false;
		}

		//if (IsOptional())
		//{
		//	file->WriteLine("_list.exists = true;");
		//	file->WriteLine("_list.value->push_back(tmp);");
		//}
		//else
		file->WriteLine("_list.push_back(tmp);");
		file->outdent();
		file->WriteLine("}");
	}
	//if (IsOptional())
	//{
	//	file->outdent();
	//	file->WriteLine("}");
	//}
	return true;

}
tsStringBase SequenceOfNode::BuildSequenceOfMetadataLine(const tsStringBase& structureName)
{
	return "#error SequenceOfNode::BuildSequenceOfMetadataLine is needed";
	//tsCryptoString tmp, tmp2;
	//tsCryptoString type = Elements()[0]->ElementType();

	//tmp << "{ (Asn1Metadata::FieldFlags)(";
	//tmp2 = getMetadataType(type);
	//if (tmp2.size() == 0)
	//{
	//	throw std::runtime_error((tsCryptoString() << "Unknown node type of " << type).c_str());
	//}
	//tmp << tmp2;

	//tmp << " | Asn1Metadata::tp_array";

	//if (IsOptional())
	//{
	//	tmp << " | Asn1Metadata::tp_optional";
	//}
	//tmp << "), ";

	//if (type == "Null")
	//	tmp << "-1, -1, ";
	//else
	//{
	//	if (IsOptional())
	//	{
	//		// TODO:  Handle class types here
	//		tmp << "offsetof(" + structureName + ", _list)" << GetOptionalValueOffset() << GetSubobjectValueOffset() << ", ";

	//		if (isSequence(type) && !IsArray())
	//			tmp << "-1, ";
	//		else
	//		{
	//			// TODO:  Handle class types here
	//			tmp << "offsetof(" + structureName + ", _list)" << GetOptionalExistsOffset() << ", ";
	//		}
	//	}
	//	else
	//	{
	//		tmp << "offsetof(" + structureName + ", _list)" << GetSubobjectValueOffset() << ", -1, ";
	//	}
	//}
	//tmp << GetTagOffset(structureName) << GetTypeOffset(structureName);
	//tmp << "-1, "; // choice field
	//tmp << "-1, "; // Secondary field

	//tmp << "__" << structureName << "_Metadata_array_list, 1, "; // Sub metadata fields

	//tmp << BuildTagString() << ", " << BuildTypeString() << ", ";
	//if (JSONName().size() > 0)
	//	tmp << "nullptr";
	//else
	//	tmp << "\"" << JSONName() << "\"";
	//tmp << ", \"_list\", ";
	//if (Default().size() > 0)
	//	tmp << "\"" << Default() << "\"";
	//else
	//	tmp << "nullptr";
	//tmp << ", nullptr, nullptr, nullptr, nullptr },"; // TODO:  Need to implement these
	//return tmp;
}
bool SequenceOfNode::WriteSubMetadata(std::shared_ptr<FileNode> files, const tsStringBase& structureName, const tsStringBase& PODstructureName)
{
	files->Source()->WriteLine("static const struct Asn1Metadata __" + structureName + "_Metadata_array_" + Name() + "[] =");
	files->Source()->WriteLine("{");
	files->Source()->indent();

	std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(_fields[0]);
	if (ele->StructureName().size() > 0)
	{
		if (ele->StructureName().right(ele->Name().size() + 1) == "_" + ele->Name())
		{
			tsStringBase tmp(ele->StructureName());
			tmp.resize(tmp.size() - ele->Name().size() - 1);
			files->Source()->WriteLine(Elements()[0]->BuildMetadataLine(tmp, ele->PODStructureName()));
		}
		else
			files->Source()->WriteLine(Elements()[0]->BuildMetadataLine(ele->StructureName(), ele->PODStructureName()));
	}
	else
		files->Source()->WriteLine(Elements()[0]->BuildMetadataLine(structureName, PODstructureName));

	files->Source()->outdent();
	files->Source()->WriteLine("};");
	files->Source()->WriteLine();
	return true;
}
bool SequenceOfNode::WriteAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName)
{
	std::shared_ptr<Element> ele = Elements()[0];

	{
		files->Header()->WriteLine("size_t get_" + Name() + "_count() const;");
		files->Source()->WriteLine("size_t " + structureName + "::get_" + Name() + "_count() const { return _" + Name() + "->size(); }");

		files->Header()->WriteLine("void clear_" + Name() + "();");
		files->Source()->WriteLine("void " + structureName + "::clear_" + Name() + "() { _" + Name() + "->clear(); }");

		files->Header()->WriteLine("void delete_" + Name() + "_at(size_t index);");
		files->Source()->WriteLine("void " + structureName + "::delete_" + Name() + "_at(size_t index) { auto it = _" + Name() + "->begin(); std::advance(it, index); _" + Name() + "->erase(it); }");

		if (ele->IsOptional())
		{
			throw std::runtime_error("Optional elements are not supported within SequenceOf.");
		}
		else
		{
			if (ele->StructureName().size() == 0)
			{
				files->Header()->WriteLine(ele->CppType() + " get_" + Name() + "_at(size_t index) const;");
				files->Source()->WriteLine(ele->CppType() + " " + structureName + "::get_" + Name() + "_at(size_t index) const { return _" + Name() + "->at(index); }");

				if (isBasicType(ele->CppType()))
				{
					files->Header()->WriteLine("void set_" + Name() + "_at(size_t index, " + ele->CppType() + " setTo);");
					files->Source()->WriteLine("void " + structureName + "::set_" + Name() + "_at(size_t index, " + ele->CppType() + " setTo) { _" + Name() + "->at(index) = setTo; }");

					files->Header()->WriteLine("void clear_" + Name() + "_at(size_t index);");
					files->Source()->WriteLine("void " + structureName + "::clear_" + Name() + "_at(size_t index) { _" + Name() + "->at(index) = " + ele->Initializer() + "; }");
				}
				else
				{
					files->Header()->WriteLine("void set_" + Name() + "_at(size_t index, const " + ele->CppType() + "& setTo);");
					files->Source()->WriteLine("void " + structureName + "::set_" + Name() + "_at(size_t index, const " + ele->CppType() + "& setTo) { _" + Name() + "->at(index) = setTo; }");

					files->Header()->WriteLine("void set_" + Name() + "_at(size_t index, " + ele->CppType() + "&& setTo);");
					files->Source()->WriteLine("void " + structureName + "::set_" + Name() + "_at(size_t index, " + ele->CppType() + "&& setTo) { _" + Name() + "->at(index) = std::move(setTo); }");

					files->Header()->WriteLine("void clear_" + Name() + "_at(size_t index);");
					files->Source()->WriteLine("void " + structureName + "::clear_" + Name() + "_at(size_t index) { _" + Name() + "->at(index).clear(); }");

					files->Header()->WriteLine("void add_" + Name() + "(const " + ele->CppType() + "& setTo);");
					files->Source()->WriteLine("void " + structureName + "::add_" + Name() + "(const " + ele->CppType() + "& setTo) { ");
					files->Source()->WriteLine("    if (!_" + Name() + ")");
					files->Source()->WriteLine("        _" + Name() + " = asdfadsf");
					files->Source()->WriteLine("    _" + Name() + "->push_back(setTo);");
					files->Source()->WriteLine("}");
				}
			}
			else
			{
				files->Header()->WriteLine("const " + ele->FullStructureName() + "* get_" + Name() + "_at(size_t index) const;");
				files->Source()->WriteLine("const " + ele->FullStructureName() + "* " + structureName + "::get_" + Name() + "_at(size_t index) const { const std::shared_ptr<Asn1DataBaseClass>& tmp = _" + Name() + "->at(index); if (!!tmp) return dynamic_cast<const " + ele->FullStructureName() + "*>(&*tmp); return nullptr; }");

				files->Header()->WriteLine(ele->FullStructureName() + "& get_" + Name() + "_at(size_t index);");
				files->Source()->WriteLine(ele->FullStructureName() + "& " + structureName + "::get_" + Name() + "_at(size_t index) { std::shared_ptr<Asn1DataBaseClass>& tmp = _" + Name() + "->at(index); if (!!tmp) return *dynamic_cast<" + ele->FullStructureName() + "*>(&*tmp); throw ArgumentException(\"Invalid index\"); }");

				files->Header()->WriteLine("void set_" + Name() + "_at(size_t index, const " + ele->CppType() + "& setTo);");
				files->Source()->WriteLine("void " + structureName + "::set_" + Name() + "_at(size_t index, const " + ele->CppType() + "& setTo) { if (index >= _" + Name() + "->size()) return; *(" + ele->CppType() + "*)_" + Name() + "->at(index).get() = setTo; }");

				files->Header()->WriteLine("void set_" + Name() + "_at(size_t index, " + ele->CppType() + "&& setTo);");
				files->Source()->WriteLine("void " + structureName + "::set_" + Name() + "_at(size_t index, " + ele->CppType() + "&& setTo) { if (index >= _" + Name() + "->size()) return; *(" + ele->CppType() + "*)_" + Name() + "->at(index).get() = std::move(setTo); }");

				files->Header()->WriteLine("void clear_" + Name() + "_at(size_t index);");
				files->Source()->WriteLine("void " + structureName + "::clear_" + Name() + "_at(size_t index) { _" + Name() + "->at(index)->clear(); }");

				files->Header()->WriteLine("void add_" + Name() + "(const " + ele->CppType() + "& setTo);");
				files->Source()->WriteLine("void " + structureName + "::add_" + Name() + "(const " + ele->CppType() + "& setTo) {");
				files->Source()->WriteLine("    if (!_" + Name() + ")");
				files->Source()->WriteLine("        _" + Name() + " = asdfadsf");
				files->Source()->WriteLine("    _" + Name() + "->push_back(std::shared_ptr<Asn1DataBaseClass>(setTo.clone()));");
				files->Source()->WriteLine("}");
			}
		}
	}

	files->Header()->WriteLine();
	files->Source()->WriteLine();
	return true;
}
bool SequenceOfNode::WriteSequenceOfAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName)
{
	std::shared_ptr<Element> ele = Elements()[0];
	tsStringBase ns;

	if (!!ele->NameSpace())
	{
		ns = ele->NameSpace()->ToString();
	}

	//if (IsOptional())
	//{
	//	files->Header()->WriteLine("size_t size() const;");
	//	files->Source()->WriteLine("size_t " + structureName + "::size() const { if (_list.exists) return _list.value->size(); return 0; }");

	{
		if (ele->IsOptional())
		{
			throw std::runtime_error("Optional elements are not supported within SequenceOf.");
		}
		else
		{
			if (ele->StructureName().size() == 0)
			{
				files->Header()->WriteLine("size_t size() const {");
				files->Header()->WriteLine("    return _list.size();");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void clear_list() {");
				files->Header()->WriteLine("    _list.clear();");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void delete_at(size_t index) {");
				files->Header()->WriteLine("    _list.remove(index);");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine(ele->CppType() + " get_at(size_t index) const {");
				files->Header()->WriteLine("    return _list.at(index);");
				files->Header()->WriteLine("}");

				if (isBasicType(ele->CppType()))
				{
					files->Header()->WriteLine("void set_at(size_t index, " + ele->CppType() + " setTo) {");
					files->Header()->WriteLine("    _list.at(index) = setTo;");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("void clear_at(size_t index) {");
					files->Header()->WriteLine("    _list.at(index) = " + ele->Initializer() + ";");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("void add(" + ele->CppType() + " setTo) {");
					files->Header()->WriteLine("    _list.push_back(setTo);");
					files->Header()->WriteLine("}");
				}
				else
				{
					files->Header()->WriteLine("void set_at(size_t index, const " + ele->CppType() + "& setTo) {");
					files->Header()->WriteLine("    _list.at(index) = setTo;");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("void set_at(size_t index, " + ele->CppType() + "&& setTo) {");
					files->Header()->WriteLine("    _list.at(index) = std::move(setTo);");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("void clear_at(size_t index) {");
					files->Header()->WriteLine("    _list.at(index).clear();");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("void add(const " + ele->CppType() + "& setTo) {");
					files->Header()->WriteLine("    _list.push_back(setTo);");
					files->Header()->WriteLine("}");
				}
			}
			else
			{
				files->Header()->WriteLine("size_t size() const {");
				files->Header()->WriteLine("    return _list.size();");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void clear_list() {");
				files->Header()->WriteLine("    _list.clear();");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void delete_at(size_t index) {");
				files->Header()->WriteLine("    _list.remove(index);");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("const " + ns + ele->PODStructureName() + "& get_at(size_t index) const {");
				files->Header()->WriteLine("    return *static_cast<const " + ns + ele->PODStructureName() + "*>(_list.at(index).get());");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine(ns + ele->PODStructureName() + "& get_at(size_t index) {");
				files->Header()->WriteLine("    return *static_cast<" + ns + ele->PODStructureName() + "*>(_list.at(index).get());");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void set_at(size_t index, const " + ns + ele->PODStructureName() + "& setTo) {");
				files->Header()->WriteLine("    if (index >= _list.size())");
				files->Header()->WriteLine("        _list.push_back(tscrypto::Asn1ObjectWrapper(&" + ns + ele->PODStructureName() + "::deletor, &" + ns + ele->PODStructureName() + "::cloner, " + ns + ele->PODStructureName() + "::cloner((void*)&setTo)));");
				files->Header()->WriteLine("    else");
				files->Header()->WriteLine("	    *static_cast<" + ns + ele->PODStructureName() + "*>(_list.at(index).get()) = setTo;");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void set_at(size_t index, " + ns + ele->PODStructureName() + "&& setTo) {");
				files->Header()->WriteLine("    if (index >= _list.size())");
				files->Header()->WriteLine("        _list.push_back(tscrypto::Asn1ObjectWrapper(&" + ns + ele->PODStructureName() + "::deletor, &" + ns + ele->PODStructureName() + "::cloner, (void*)new " + ns + ele->PODStructureName() + "(std::move(setTo))));");
				files->Header()->WriteLine("    else");
				files->Header()->WriteLine("		*static_cast<" + ns + ele->PODStructureName() + "*>(_list.at(index).get()) = std::move(setTo);");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void clear_at(size_t index) {");
				files->Header()->WriteLine("    (static_cast<" + ns + ele->PODStructureName() + "*>(_list.at(index).get()))->clear();");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void add(const " + ns + ele->PODStructureName() + "& setTo) {");
				files->Header()->WriteLine("    _list.push_back(tscrypto::Asn1ObjectWrapper(&" + ns + ele->PODStructureName() + "::deletor, &" + ns + ele->PODStructureName() + "::cloner, " + ns + ele->PODStructureName() + "::cloner((void*)&setTo)));");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("void add(" + ns + ele->PODStructureName() + "&& setTo) {");
				files->Header()->WriteLine("    _list.push_back(tscrypto::Asn1ObjectWrapper(&" + ns + ele->PODStructureName() + "::deletor, &" + ns + ele->PODStructureName() + "::cloner, (void*)new " + ns + ele->PODStructureName() + "(std::move(setTo))));");
				files->Header()->WriteLine("}");
			}
		}
	}

	files->Header()->WriteLine();
	files->Source()->WriteLine();
	return true;
}
bool SequenceOfNode::WriteMetadataLine(std::shared_ptr<FileNode> files, int& versionEleCount)
{
	for (auto e : Elements())
	{
		tsStringBase oldName = e->Name();
		e->Name("list");
		files->Source()->WriteLine(e->BuildMetadataLine(FullStructureName(), PODStructureName()));
		e->Name(oldName);
	}
	return true;
}
bool SequenceOfNode::WritePODStructure(std::shared_ptr<FileNode> files)
{
	if (!Import())
	{
		tsStringBase ns;

		if (!!NameSpace())
		{
			ns = NameSpace()->ToString();
		}

		if (PODStructureWritten())
			return true;
		PODStructureWritten(true);

		for (auto& ele : Dependencies())
		{
			if (!!ele && !ele->PODStructureWritten())
			{
				if (!ele->WritePODStructure(files))
					return false;
			}
		}
		for (auto& ele : Elements())
		{
			if (!ele->WritePODStructure(files))
				return false;
		}

		files->Header()->SetNamespace(NameSpace());

		files->Header()->WriteLine("// ----------------------------------------------------------------");
		files->Header()->WriteLine();

		files->Header()->WriteLine("struct " + files->ExportSymbol() + PODStructureName() + " final {");
		files->Source()->WriteLine("// " + PODStructureName());
		files->Header()->WriteLine("private:");
		files->Header()->WriteLine("    " + _arrayType + " _list;");
		files->Header()->WriteLine("public:");
		files->Header()->indent();
		// Allocators
		files->Header()->WriteLine("static void* operator new(std::size_t count) {");
		files->Header()->WriteLine("	return tscrypto::cryptoNew(count);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void* operator new[](std::size_t count) {");
		files->Header()->WriteLine("	return tscrypto::cryptoNew(count);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("	static void operator delete(void* ptr) {");
		files->Header()->WriteLine("	tscrypto::cryptoDelete(ptr);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void operator delete[](void* ptr) {");
		files->Header()->WriteLine("	tscrypto::cryptoDelete(ptr);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine();

		// Default constructor
		files->Header()->WriteLine(PODStructureName() + "()");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("    static_assert(std::is_standard_layout<" + PODStructureName() + ">::value, \"" + PODStructureName() + " is not a standard layout type.\");");
		files->Header()->WriteLine("}");

		// Copy constructor
		files->Header()->WriteLine(PODStructureName() + "(const " + PODStructureName() + "& obj)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("    _list = obj._list;");
		files->Header()->WriteLine("}");


		// Move Constructor
		files->Header()->WriteLine(PODStructureName() + "(" + PODStructureName() + "&& obj) : _list(std::move(obj._list))");
		files->Header()->WriteLine("{");
//		files->Header()->WriteLine("    obj._list = " + _arrayCreateType + "();");
		files->Header()->WriteLine("}");

		// Assignment operator
		files->Header()->WriteLine(PODStructureName() + "& operator=(const " + PODStructureName() + "& obj)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (&obj != this)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("_list = obj._list;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("return *this;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// Move operator
		files->Header()->WriteLine(PODStructureName() + "& operator=(" + PODStructureName() + "&& obj)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (&obj != this)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("_list = std::move(obj._list);");
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("return *this;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// clear
		files->Header()->WriteLine("void clear() { _list.clear(); }");

		// Write data accessors
		files->Header()->WriteLine("// Accessors");
		WriteSequenceOfAccessors(files, PODStructureName());
		files->Header()->WriteLine();

		// Write user functions
		files->Header()->WriteLine("// User Functions");
		for (auto f : Functions())
		{
			files->Header()->WriteLine(f->ReturnType() + " " + f->Name() + "(" + f->Parameters() + ")" + f->Suffix() + ";");
		}
		_WriteUserFunctions(files->Source());

		files->Header()->WriteLine("");
		files->Header()->WriteLine("// Metadata Helpers");
		files->Header()->WriteLine("static tscrypto::Asn1Metadata2::matchResult NodeMatches(const std::shared_ptr<tscrypto::TlvNode> node, const tscrypto::Asn1Metadata2* metadata);");
		files->Source()->WriteLine("tscrypto::Asn1Metadata2::matchResult " + ns + PODStructureName() + "::NodeMatches(const std::shared_ptr<tscrypto::TlvNode> node, const tscrypto::Asn1Metadata2* metadata)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	for (size_t i = 0; i < __Metadata_main_count; i++)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		if (NodeMatchesMetadata(node, &__Metadata_main[i]) == tscrypto::Asn1Metadata2::good)");
		files->Source()->WriteLine("			return tscrypto::Asn1Metadata2::good;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	if (metadata->fieldFlags & tscrypto::Asn1Metadata2::tp_optional)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		return tscrypto::Asn1Metadata2::defaulted;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	return tscrypto::Asn1Metadata2::mismatch;");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("");
		files->Header()->WriteLine("// Metadata");

		//if (Export())
		//{
		//	files->Header()->WriteLine("const int __" + StructureName() + "_tag = " << BuildTagString() << ";");
		//	files->Header()->WriteLine("const int __" + StructureName() + "_type = " << BuildTypeString() << ";");
		//	files->Header()->WriteLine();
		//}
		//else
		//{
		files->Header()->WriteLine(tsStringBase().append("static const int __tag = ").append(BuildTagString()).append(";"));
		files->Header()->WriteLine(tsStringBase().append("static const int __type = ").append(BuildTypeString()).append(";"));
		files->Header()->WriteLine();
		//}

		if (!FieldMetadataWritten())
		{
			FieldMetadataWritten(true);
			files->Header()->SetNamespace(NameSpace());

			//if (Export())
			//{

			//	// Write the field metadata here
			//	files->Source()->WriteLine("const struct Asn1Metadata2 __" + StructureName() + "_Metadata_main[__" + StructureName() + "_Metadata_main_count] =");
			//	files->Source()->WriteLine("{");
			//	files->Source()->indent();
			//	for (auto e : Elements())
			//	{
			//		files->Source()->WriteLine(e->BuildMetadataLine(StructureName()));
			//	}
			//	files->Source()->outdent();
			//	files->Source()->WriteLine("};");
			//	files->Source()->WriteLine();

			//	files->Header()->WriteLine("const size_t __" + StructureName() + "_Metadata_main_count = " + (tsCryptoString() << Elements().size()) + ";");
			//	files->Header()->WriteLine("extern const struct Asn1Metadata2 __" + StructureName() + "_Metadata_main[__" + StructureName() + "_Metadata_main_count];");
			//	files->Header()->WriteLine();
			//}
			//else
			{
				// Write the field metadata here
				files->Header()->WriteLine(tsStringBase().append("static const size_t __Metadata_main_count = ").append((int32_t)Elements().size()).append(";"));

				files->Header()->WriteLine(tsStringBase().append("static const struct tscrypto::Asn1Metadata2 __Metadata_main[__Metadata_main_count];"));

				files->Source()->WriteLine(tsStringBase().append("const struct tscrypto::Asn1Metadata2 " + ns + PODStructureName() + "::__Metadata_main[" + ns + PODStructureName() + "::__Metadata_main_count] ="));
				files->Source()->WriteLine("{");
				files->Source()->indent();
				for (auto e : Elements())
				{
					tsStringBase name(e->Name());
					e->Name("list");
					files->Source()->WriteLine(e->BuildMetadataLine(FullStructureName(), ns + PODStructureName()));
					e->Name(name);
				}
				files->Source()->outdent();
				files->Source()->WriteLine("};");
				files->Source()->WriteLine();
			}
			{
				tsStringBase tmp;

				tmp.append("const struct tscrypto::Asn1StructureDefinition2 " + ns + PODStructureName() + "::__Definition = {").append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
				tmp.append(ns + PODStructureName() + "::__Metadata_main, " + ns + PODStructureName() + "::__Metadata_main_count, nullptr, 0, ");
				tmp.append("nullptr, ");
				tmp.append("\"0\", false");
				tmp.append("};");
				files->Source()->WriteLine(tmp);
				files->Header()->WriteLine("static const struct tscrypto::Asn1StructureDefinition2 __Definition;");
			}
			files->Source()->WriteLine();

		}

		files->Header()->WriteLine("static void deletor(void* obj)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	delete (" + ns + PODStructureName() + "*)obj;");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void* cloner(void* obj)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return new " + ns + PODStructureName() + "(*(" + ns + PODStructureName() + "*)obj);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static tscrypto::Asn1ObjectWrapper creator()");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return tscrypto::Asn1ObjectWrapper(deletor, cloner, new " + ns + PODStructureName() + ");");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static bool encoder(void* obj, std::shared_ptr<tscrypto::TlvNode> parent)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return ((" + ns + PODStructureName() + "*)obj)->Encode(parent);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static bool decoder(void* obj, const std::shared_ptr<tscrypto::TlvNode> root)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return ((" + ns + PODStructureName() + "*)obj)->DecodeChildren(root);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void clearer(void* obj)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	((" + ns + PODStructureName() + "*)obj)->_list.clear();");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine();

		// Encoders and Decoders
		files->Header()->WriteLine();
		// Encode
		files->Header()->WriteLine("bool Encode(tscrypto::tsCryptoData& output, bool withoutWrapper = false)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
		files->Header()->WriteLine();
		files->Header()->WriteLine("output.clear();");
		files->Header()->WriteLine();
		files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition.tag);");
		files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition.type);");
		files->Header()->WriteLine("if (!EncodeChildren(doc))");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine();
		files->Header()->WriteLine("if (withoutWrapper || __Definition.dontWrap)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("output = doc->DocumentElement()->InnerData();");
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("else");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	output = doc->DocumentElement()->OuterData();");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("return true;");
		files->Header()->outdent();
		//files->Header()->indent();
		//files->Header()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("output.clear();");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		//files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		//files->Header()->WriteLine("if (!EncodeChildren(doc))");
		//files->Header()->WriteLine("	return false;");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("output = doc->DocumentElement()->InnerData();");
		//files->Header()->WriteLine("return true;");
		//files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine("bool Encode(std::shared_ptr<tscrypto::TlvNode> parent)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	std::shared_ptr<tscrypto::TlvNode> top;");
		files->Header()->WriteLine("	parent->AppendChild(top = parent->OwnerDocument().lock()->CreateTlvNode(__Definition.tag, (uint8_t)__Definition.type));");
		files->Header()->WriteLine("	if (!EncodeChildren(top))");
		files->Header()->WriteLine("		return false;");
		files->Header()->WriteLine("	return true;");
		//files->Header()->WriteLine("	if (!EncodeChildren(parent))");
		//files->Header()->WriteLine("		return false;");
		//files->Header()->WriteLine("	return true;");
		files->Header()->WriteLine("}");

		// Decode
		files->Header()->WriteLine("bool Decode(const tscrypto::tsCryptoData& input, bool withoutWrapper = false)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
		files->Header()->WriteLine();
		files->Header()->WriteLine("if (withoutWrapper || __Definition.dontWrap)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition.tag);");
		files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition.type);");
		files->Header()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		files->Header()->WriteLine("	return false;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("else");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine("}");
		files->Header()->outdent();
		files->Header()->WriteLine();
		files->Header()->WriteLine("if (doc->DocumentElement()->Tag() != __Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__Definition.type)");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine();
		files->Header()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		files->Header()->outdent();
		//files->Header()->indent();
		//files->Header()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		//files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		//files->Header()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		//files->Header()->WriteLine("	return false;");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("if (doc->DocumentElement()->Tag() != __" + StructureName() + "_Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__" + StructureName() + "_Definition.type)");
		//files->Header()->WriteLine("	return false;");
		//files->Header()->WriteLine();
		//files->Header()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		//files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine();

		// Encode Children
		files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvDocument> doc)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return EncodeChildren(doc->DocumentElement());");
		files->Header()->WriteLine("}");

		files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvNode> root)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("return EncodeSequenceOfTlv(this, root, __Metadata_main, offsetof(" + PODStructureName() + ", _list));");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// Decode Children
		files->Header()->WriteLine("bool DecodeChildren(const std::shared_ptr<tscrypto::TlvNode> root)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("return DecodeSequenceOfTlv(this, root, __Metadata_main, offsetof(" + PODStructureName() + ", _list));");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine();

		// Write encode function definitions
		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			files->Header()->WriteLine("tscrypto::JSONObject toJSON() const { tscrypto::JSONObject obj; if (!toJSON(obj)) obj.clear(); return obj; }");
			files->Header()->WriteLine("bool toJSON(tscrypto::JSONObject& obj) const");
			files->Header()->WriteLine("{");
			files->Header()->indent();

			for (auto e : Elements())
			{
				if (!/*e->*/ WriteToJSON(files->Header()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Header()->WriteLine("return true;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const tscrypto::tsCryptoStringBase& json) { tscrypto::JSONObject obj; if (!obj.FromJSON(json)) return false; return fromJSON(obj); }");
			files->Header()->WriteLine("bool fromJSON(const tscrypto::JSONObject& obj)");
			files->Header()->WriteLine("{");
			files->Header()->indent();
			files->Header()->WriteLine("clear();");

			for (auto e : Elements())
			{
				if (!/*e->*/WriteFromJSON(files->Header()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Header()->WriteLine("");
			files->Header()->WriteLine("return true;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");
		}

		files->Header()->outdent();
		files->Header()->WriteLine("};");
		files->Header()->WriteLine();
	}
	return true;
}
bool SequenceOfNode::WriteStructure(std::shared_ptr<FileNode> files)
{
	if (!Import())
	{
		if (StructureWritten())
			return true;
		StructureWritten(true);

		for (auto& ele : Dependencies())
		{
			if (!!ele && !ele->StructureWritten())
			{
				if (!ele->WriteStructure(files))
					return false;
			}
		}
		for (auto& ele : Elements())
		{
			if (!ele->WriteStructure(files))
				return false;
		}

		files->Header()->SetNamespace(NameSpace());


		files->Source()->SetNamespace(NameSpace());
		files->Source()->WriteLine("// ----------------------------------------------------------------");
		files->Source()->WriteLine("// " + StructureName());
		files->Source()->WriteLine();

		for (auto e : Elements())
		{
			e->WriteSubMetadata(files, StructureName(), PODStructureName());
		}

		files->Source()->WriteLine("static const struct Asn1Metadata __" + StructureName() + "_Metadata_main[] =");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		int versionEleCount = 0;
		WriteMetadataLine(files, versionEleCount);
		files->Source()->outdent();
		files->Source()->WriteLine("};");

		files->Source()->WriteLine("static const size_t __" + StructureName() + "_Metadata_main_count = 1;");
		files->Source()->WriteLine();


		{
			tsStringBase tmp;

			tmp.append("static const struct Asn1StructureDefinition __").append(StructureName()).append("_Definition = {").append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
			tmp.append("__" + StructureName() + "_Metadata_main, __").append(StructureName()).append("_Metadata_main_count, nullptr, 0, ");
			tmp.append("nullptr, ");
			tmp.append("\"0\", false");
			tmp.append("};");
			files->Source()->WriteLine(tmp);
		}
		files->Source()->WriteLine();

		//files->Header()->WriteLine("// IMPORTANT NOTE:  We are using offsetof on non-POD structs.  This may cause memory corruption in the future.  Consider rewriting with a different serializer (member functions, more specialized classes, ...");
		files->Header()->WriteLine("struct " + files->ExportSymbol() + StructureName() + " : public Asn1DataBaseClass {");

		files->Header()->indent();
		// Basic constructor
		files->Header()->WriteLine(StructureName() + "();");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "()");
		files->Source()->WriteLine("{}");

		// Copy constructor
		files->Header()->WriteLine(StructureName() + "(const " + StructureName() + "& obj);");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "(const " + StructureName() + "& obj) : _data(obj._data)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Move constructor
		files->Header()->WriteLine(StructureName() + "(" + StructureName() + "&& obj);");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "(" + StructureName() + "&& obj) : _data(std::move(obj._data))");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("}");

		// Destructor
		files->Header()->WriteLine("virtual ~" + StructureName() + "();");
		files->Source()->WriteLine(StructureName() + "::~" + StructureName() + "()");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("clear();");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Creator
		files->Header()->WriteLine("static Asn1DataBaseClass* Create() { return new " + StructureName() + "; }");

		// Destroyer
		files->Header()->WriteLine("static void Destroy(Asn1DataBaseClass* object) { if (object != nullptr) delete object; }");

		// Clearer
		files->Header()->WriteLine("static void Clear(Asn1DataBaseClass* object) { if (object != nullptr) object->clear(); }");

		// Encoders and Decoders
		files->Header()->WriteLine();
		// Encode
		files->Header()->WriteLine("virtual bool Encode(tscrypto::tsCryptoData& output, bool withoutWrapper = false) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Encode(tscrypto::tsCryptoData& output, bool withoutWrapper)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("output.clear();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		files->Source()->WriteLine("if (!EncodeChildren(doc))");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (withoutWrapper || __" + StructureName() + "_Definition.dontWrap)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("output = doc->DocumentElement()->InnerData();");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("else");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	output = doc->DocumentElement()->OuterData();");
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		//files->Source()->indent();
		//files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("output.clear();");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		//files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		//files->Source()->WriteLine("if (!EncodeChildren(doc))");
		//files->Source()->WriteLine("	return false;");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("output = doc->DocumentElement()->InnerData();");
		//files->Source()->WriteLine("return true;");
		//files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool Encode(std::shared_ptr<tscrypto::TlvNode> parent) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Encode(std::shared_ptr<tscrypto::TlvNode> parent)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	std::shared_ptr<tscrypto::TlvNode> top;");
		files->Source()->WriteLine("	parent->AppendChild(top = parent->OwnerDocument().lock()->CreateTlvNode(__" + StructureName() + "_Definition.tag, (uint8_t)__" + StructureName() + "_Definition.type));");
		files->Source()->WriteLine("	if (!EncodeChildren(top))");
		files->Source()->WriteLine("		return false;");
		files->Source()->WriteLine("	return true;");
		//files->Source()->WriteLine("	if (!EncodeChildren(parent))");
		//files->Source()->WriteLine("		return false;");
		//files->Source()->WriteLine("	return true;");
		files->Source()->WriteLine("}");

		// Decode
		files->Header()->WriteLine("virtual bool Decode(const tscrypto::tsCryptoData& input, bool withoutWrapper = false) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Decode(const tscrypto::tsCryptoData& input, bool withoutWrapper)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (withoutWrapper || __" + StructureName() + "_Definition.dontWrap)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		files->Source()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		files->Source()->WriteLine("	return false;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("else");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine("}");
		files->Source()->outdent();
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (doc->DocumentElement()->Tag() != __" + StructureName() + "_Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__" + StructureName() + "_Definition.type)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		files->Source()->outdent();
		//files->Source()->indent();
		//files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		//files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		//files->Source()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		//files->Source()->WriteLine("	return false;");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("if (doc->DocumentElement()->Tag() != __" + StructureName() + "_Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__" + StructureName() + "_Definition.type)");
		//files->Source()->WriteLine("	return false;");
		//files->Source()->WriteLine();
		//files->Source()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		//files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Encode Children
		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<tscrypto::TlvDocument> doc) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<tscrypto::TlvDocument> doc)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	return EncodeChildren(doc->DocumentElement());");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<tscrypto::TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<tscrypto::TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("return EncodeSequenceOfTlv(this, root, __" + StructureName() + "_Metadata_main, offsetof(" + PODStructureName() + ", _list));");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Decode Children
		files->Header()->WriteLine("virtual bool DecodeChildren(const std::shared_ptr<tscrypto::TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::DecodeChildren(const std::shared_ptr<tscrypto::TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("return DecodeSequenceOfTlv(this, root, __" + StructureName() + "_Metadata_main, offsetof(" + PODStructureName() + ", _list));");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Equality operator
		files->Header()->WriteLine("virtual bool operator==(const Asn1DataBaseClass& obj) const override;");
		files->Source()->WriteLine("bool " + StructureName() + "::operator==(const Asn1DataBaseClass& obj) const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "* o = dynamic_cast<const " + StructureName() + "*>(&obj);");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (o == nullptr) return false;");
		files->Source()->WriteLine("if (o == this) return true;");
		files->Source()->WriteLine("if (!(_data._list == o->_data._list)) return false;");
		//if (!IsOptional())
		{
			files->Source()->WriteLine("if (!!_data._list)");
			files->Source()->WriteLine("{");
			files->Source()->WriteLine("	if (_data._list->size() != o->_data._list->size()) return false;");
			files->Source()->WriteLine("	for (size_t i = 0; i < _data._list->size(); i++)");
			files->Source()->WriteLine("	{");
			files->Source()->WriteLine("		if (!(_data._list->at(i) == o->_data._list->at(i))) return false;");
			files->Source()->WriteLine("	}");
			files->Source()->WriteLine("}");
		}
		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine();


		// clear
		files->Header()->WriteLine("virtual void clear() override;");
		files->Source()->WriteLine("void " + StructureName() + "::clear()");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	ClearSequenceOfTlv(this, __" + StructureName() + "_Metadata_main, offsetof(" + PODStructureName() + ", _list));");
		files->Source()->WriteLine("}");


		// clone
		files->Header()->WriteLine("virtual Asn1DataBaseClass* clone() const override;");
		files->Source()->WriteLine("Asn1DataBaseClass* " + StructureName() + "::clone() const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + " *o = new " + StructureName() + "(*this);");
		files->Source()->WriteLine("");
		files->Source()->WriteLine("return o;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Assignment operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(const Asn1DataBaseClass& obj) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(const Asn1DataBaseClass& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "*obj = dynamic_cast<const " + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_data = obj->_data;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Assignment operator
		files->Header()->WriteLine(StructureName() + "& operator=(const " + StructureName() + "& obj);");
		files->Source()->WriteLine(StructureName() + "& " + StructureName() + "::operator=(const " + StructureName() + "& obj)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_data = obj._data;");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Move operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(Asn1DataBaseClass&& obj) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(Asn1DataBaseClass&& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + "* obj = dynamic_cast<" + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_data = std::move(obj->_data);");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();


		// Write encode function definitions
		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			files->Header()->WriteLine("virtual tscrypto::JSONObject toJSON() const override { return Asn1DataBaseClass::toJSON(); }");
			files->Header()->WriteLine("virtual bool fromJSON(const char* json) override { return Asn1DataBaseClass::fromJSON(json); }");
			files->Header()->WriteLine("virtual bool fromJSON(const tscrypto::tsCryptoStringBase& json) override { return Asn1DataBaseClass::fromJSON(json); }");

			files->Header()->WriteLine("bool toJSON(tscrypto::JSONObject& obj) const override;");
			files->Source()->WriteLine("bool " + StructureName() + "::toJSON(tscrypto::JSONObject& obj) const");
			files->Source()->WriteLine("{");
			files->Source()->indent();

			for (auto e : Elements())
			{
				if (!/*e->*/ WriteToJSON(files->Source()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const tscrypto::JSONObject& obj) override;");
			files->Source()->WriteLine("bool " + StructureName() + "::fromJSON(const tscrypto::JSONObject& obj)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("clear();");

			for (auto e : Elements())
			{
				if (!/*e->*/WriteFromJSON(files->Source()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Source()->WriteLine("");
			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
		}

		// Write fields
		files->Header()->WriteLine("// Data fields");

		files->Header()->WriteLine(PODStructureName() + " _data;");
		files->Header()->WriteLine("virtual void* getData() override { return (void*)&_data; }");
		files->Header()->WriteLine("virtual const void* getData() const override { return (const void*)&_data; }");

		files->Header()->WriteLine();
		WriteSequenceOfAccessors(files, StructureName());
		files->Header()->WriteLine();

		// Write user functions
		for (auto f : Functions())
		{
			files->Header()->WriteLine(f->ReturnType() + " " + f->Name() + "(" + f->Parameters() + ")" + f->Suffix() + ";");
		}

		files->Header()->outdent();
		files->Header()->WriteLine("};");

		_WriteUserFunctions(files->Source());


		// Write metadata externs
		files->Header()->WriteLine();

		//// Now write the encoder functions and metadata for each sequence/choice
		for (auto e : Elements())
		{
			if (!e->WriteUserFunctions(files->Source()))
			{
				AddError("xml2Asn1CodeGen", "", "Unable to write the user defined functions.\n");
				return false;
			}
		}
	}
	return true;
}
bool SequenceOfNode::_WriteUserFunctions(File* file)
{
	tsStringBase ns;

	if (!!NameSpace())
		ns = NameSpace()->ToString();

	if (Functions().size() > 0)
	{
		file->WriteLine();
		file->WriteLine("// User defined functions");
	}
	for (auto f : Functions())
	{
		if (f->Description().size() > 0)
			file->WriteLine(f->Description());
		file->WriteLine(f->ReturnType() + " " + ns + PODStructureName() + "::" + f->Name() + "(" + f->Parameters() + ")" + f->Suffix());
		file->WriteLine("{");
		file->indent();

		file->WriteLine(f->Body().Trim("\r\n"));

		file->outdent();
		file->WriteLine("}");
		file->WriteLine();
	}
	return true;
}

tsStringBase SequenceOfNode::FullName()
{
	tsStringBase _fullname;

	std::shared_ptr<Namespace> ns = NameSpace();
	if (!!ns)
	{
		_fullname = ns->ToString() + Name();
	}
	else
		_fullname = Name();
	return _fullname;
}
tsStringBase SequenceOfNode::FullStructureName()
{
	tsStringBase _fullname;

	std::shared_ptr<Namespace> ns = NameSpace();
	if (!!ns)
	{
		_fullname = ns->ToString() + StructureName();
	}
	else
		_fullname = StructureName();
	return _fullname;
}
