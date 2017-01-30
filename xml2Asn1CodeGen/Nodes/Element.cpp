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
#include "Element.h"
#include "FileNode.h"
#include "Namespace.h"
#include "SequenceFieldNode.h"

std::vector<tsStringBase> Element::_userDefinedBasicTypes;

Element::Element()
	:
	_PODstructureWritten(false),
	_structureWritten(false),
	_fieldMetadataWritten(false),
    _forwardsWritten(false),
    _containedInArray(false),
    _useNumberHandling(false),
    _isOptional(false),
    _export(false),
	_import(false)
{
	//	NameSpace = null;
}
Element::~Element()
{

}
bool Element::WriteCopyLine(File* file)
{
	file->WriteLine("_" + Name() + " = obj._" + Name() + ";");
	return true;
}
tsStringBase Element::BuildInequalityTest(const tsStringBase& rightObject)
{
	tsStringBase type = ElementType();
	tsStringBase tmp;

	if (hasSubMetafields(type))
	{
		tmp.append("!(_").append(Name()).append(" == ").append(rightObject).append("_").append(Name()).append(")");
	}
	else if (type == "Null")
	{
		tmp.append("// null fields skipped");
	}
	else
	{
		tmp.append("!(_").append(Name()).append(" == ").append(rightObject).append("_").append(Name()).append(")");
	}
	return tmp;
}
tsStringBase Element::BuildCloneLine(const tsStringBase& rightObject)
{
	tsStringBase type = ElementType();
	tsStringBase tmp;

	if (type == "Null")
	{
		tmp.append("// Null fields skipped");
	}
	else
	{
		tmp.append(rightObject).append("_").append(Name()).append(" = _").append(Name()).append(";");
	}
	return tmp;
}
tsStringBase Element::BuildCopyLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (ElementType() == "Null")
	{
		tmp.append("// Null fields skipped");
	}
	else
	{
		tmp.append("_").append(Name()).append(" = ").append(rightObject).append("_").append(Name()).append(";");
	}
	return tmp;
}
tsStringBase Element::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;


	if (ElementType() == "Null")
	{
		tmp.append("// Null fields skipped");
	}
	else
	{
		tmp.append("_").append(Name()).append(" = ").append(rightObject).append("_").append(Name()).append(";").append('\n');
		tmp.append(rightObject).append("_").append(Name()).append(" = ").append(Initializer()).append(";");
	}
	return tmp;
}
tsStringBase Element::BuildClearForMove(const tsStringBase& rightObject)
{
	tsStringBase tmp;


	if (ElementType() == "Null")
	{
		tmp.append("// Null fields skipped");
	}
	else
	{
		tmp.append(rightObject).append("_").append(Name()).append(" = ").append(Initializer()).append(";");
	}
	return tmp;
}
//tsCryptoString Element::GetOptionalElementType()
//{
//	tsCryptoString type = ElementType();
//	tsCryptoString tmp = getOptionalType(type);
//
//	if (tmp.size() > 0)
//		return tmp;
//	else if (IsArray() && IsOptional())
//		return CppType();
//	throw std::runtime_error("Unsupported optional element type");
//}
//tsCryptoString Element::GetOptionalValueOffset()
//{
//	if (IsOptional())
//		return (tsCryptoString().append(" + offsetof(").append(GetOptionalElementType()).append(", value)"));
//	return "";
//}
tsStringBase Element::GetSubobjectValueOffset()
{
	tsStringBase type = ElementType();

	// Asn1OptionalAny -> StructureField+OptionalValue+AnyValue - StructureField+OptionalValue+AnyTag - StructureField+OptionalValue+AnyType
	// Asn1OptBitstring-> StructureField+OptionalValue+Bitstring_dataHolder
	// Asn1OptOID      -> StructureField+OptionalValue+Asn1OID_dataHolder

	if (type == "Any")
		return (tsStringBase().append(" + offsetof(tscrypto::Asn1AnyField, value)"));
	if (type == "Bitstring")
		return (tsStringBase().append(" + offsetof(tscrypto::Asn1Bitstring, dataHolder)"));
	//if (type == "OID")
	//	return (tsCryptoString().append(" + offsetof(Asn1OID, dataHolder)"));
	return "";
}
//tsCryptoString Element::GetOptionalExistsOffset()
//{
//	tsCryptoString type = ElementType();
//
//	if (IsOptional() && !isSequence(type))
//		return (tsCryptoString().append(" + offsetof(").append(GetOptionalElementType()).append(", exists)"));
//	return "";
//}
tsStringBase Element::GetTagOffset(const tsStringBase& structureName, const tsStringBase& PODstructureName)
{
	tsStringBase type = ElementType();

	if (type == "Any")
	{
		tsStringBase tmp;

		if (ContainedInArray())
		{
			//tmp.append("0").append(GetOptionalValueOffset()).append(" + offsetof(Asn1AnyField, tag), ");
			tmp.append("0").append(" + offsetof(tscrypto::Asn1AnyField, tag), ");
		}
		else
		{
			//tmp.append("offsetof(").append(PODstructureName).append(+", _").append(Name()).append(")").append(GetOptionalValueOffset()).append(" + offsetof(Asn1AnyField, tag), ");
			tmp.append("offsetof(").append(PODstructureName).append(+", _").append(Name()).append(")").append(" + offsetof(tscrypto::Asn1AnyField, tag), ");
		}
		return tmp;
	}
	else
		return "-1, ";
}
tsStringBase Element::GetTypeOffset(const tsStringBase& structureName, const tsStringBase& PODstructureName)
{
	tsStringBase type = ElementType();

	if (type == "Any")
	{
		tsStringBase tmp;

		if (ContainedInArray())
		{
			//tmp.append("0").append(GetOptionalValueOffset()).append(" + offsetof(Asn1AnyField, type), ");
			tmp.append("0").append(" + offsetof(tscrypto::Asn1AnyField, type), ");
		}
		else
		{
			//tmp.append("offsetof(").append(PODstructureName).append(", _").append(Name()).append(")").append(GetOptionalValueOffset()).append(" + offsetof(Asn1AnyField, type), ");
			tmp.append("offsetof(").append(PODstructureName).append(", _").append(Name()).append(")").append(" + offsetof(tscrypto::Asn1AnyField, type), ");
		}
		return tmp;
	}
	else
		return "-1, ";
}

tsStringBase Element::BuildMetadataLine(const tsStringBase& structureName, const tsStringBase& PODstructureName)
{
	tsStringBase tmp, tmp2;
	tsStringBase type = ElementType();
	bool needsChoiceField = false;
	tsStringBase ns;

	if (!!NameSpace())
		ns = NameSpace()->ToString();

	tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(");

	tmp2 = getMetadataType(type);
	needsChoiceField = getNeedsChoiceField(type);
	if (tmp2.size() > 0)
	{
		tmp.append(tmp2);
	}
	else
	{
		throw std::runtime_error((tsStringBase().append("Unknown node type of ").append(type).c_str()));
	}

	//if (type == "Array")
	//{
	//	tmp << " | Asn1Metadata::tp_array";
	//}
	if (IsOptional())
	{
		tmp.append(" | tscrypto::Asn1Metadata2::tp_optional");
	}
	tmp.append("), ");

	if (type == "Null")
		tmp.append("-1, -1, ");
	else
	{
		std::shared_ptr<Element> parent = GetParentElement();

		if (!!parent && (parent->IsArray() || parent->ElementType() == "SequenceOf"))
		{
			tmp.append("0, -1, ");
		}
		else if (IsOptional())
		{
			// TODO:  Handle class types here
			if (ElementType() == "Any" && ContainedInArray())
			{
				//tmp.append(GetOptionalValueOffset()).append(GetSubobjectValueOffset()).append(", ");
				tmp.append(GetSubobjectValueOffset()).append(", ");
			}
			else
			{
				tmp.append("offsetof(").append(PODstructureName).append(", _").append(Name()).append(")").append(GetSubobjectValueOffset()).append(", ");
			}

			if (ElementType() == "Any" && ContainedInArray())
			{
				//tmp.append(GetOptionalExistsOffset()).append(", ");
				tmp.append("-1, ");
			}
			else
			{
				// TODO:  Handle class types here
				tmp.append("offsetof(").append(PODstructureName).append(", _").append(Name()).append("_exists)").append(", ");
			}
		}
		else
		{
			tmp.append("offsetof(").append(PODstructureName).append(", _").append(Name()).append(")").append(GetSubobjectValueOffset()).append(", -1, ");
		}
	}
	tmp.append(GetTagOffset(structureName, PODstructureName)).append(GetTypeOffset(structureName, PODstructureName));

	if (type == "ChoiceField")
	{
        tmp << "static_cast<int>(";
		if (!!NameSpace())
			tmp << NameSpace()->ToString();
		if (ContainedInArray())
		{
			tmp << PODStructureName() << "::__selectedItemInfo), ";
		}
		else
		{
			tmp << PODStructureName() << "::__selectedItemInfo + offsetof(" + PODstructureName + ", _" + Name() + ")), ";
		}
	}
	else
	{
		tmp.append("-1, "); // choice field
	}

	if (needsChoiceField)
	{
		if (type == "ChoiceField")
		{
			tsStringBase structName = FullStructureName().split(":").back();
			tsStringBase nspace = FullStructureName();
			nspace.resize(nspace.size() - structName.size());

			tmp.append(nspace).append("__").append(structName).append("_Metadata_main, ").append(nspace).append("__").append(structName).append("_Metadata_main_count, "); // Sub metadata fields
		}
		else
		{
			tmp.append("__").append(structureName).append("_").append(Name()).append("_Metadata_main, __").append(structureName).append("_").append(Name()).append("_Metadata_main_count, "); // Sub metadata fields
		}
	}
	else if (usesSeparateClass())
	{
		tmp.append(ns).append(PODStructureName()).append("::__Metadata_main, ").append(ns).append(PODStructureName()).append("::__Metadata_main_count, "); // Sub metadata fields
	}
	else
	{
		tmp.append("nullptr, 0, "); // Sub metadata fields
	}
	tmp.append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
	if (JSONName().size() > 0)
		tmp.append("nullptr");
	else
		tmp.append("\"").append(JSONName()).append("\"");
	tmp.append(", \"_").append(Name()).append("\", ");
	if (Default().size() > 0)
		tmp.append("\"").append(Default()).append("\", ");
	else
		tmp.append("nullptr, ");
	if (type == "ChoiceField")
	{
		tmp.append("&").append(ns + PODStructureName()).append("::NodeMatches, ");
	}
	else
		tmp.append("nullptr, ");
	if (ContainedInArray() && usesSeparateClass())
	{
		tmp 
			.append("&").append(ns + PODStructureName()).append("::creator,")
			;
	}
	else
		tmp.append("nullptr, "); // TODO:  Need to implement these
	if (usesSeparateClass())
	{
		tmp
			.append("&").append(ns + PODStructureName()).append("::encoder,")
			.append("&").append(ns + PODStructureName()).append("::decoder,")
			.append("&").append(ns + PODStructureName()).append("::clearer,")
			;
	}
	else
		tmp.append("nullptr, nullptr, nullptr, "); // TODO:  Need to implement these


	tmp.append(" },");
	return tmp;
}
tsStringBase Element::BuildTagString()
{
	return "0";
}
tsStringBase Element::BuildTypeString()
{
	return "tscrypto::TlvNode::Type_Universal";
}

bool Element::WriteToJSON(File* file)
{
	file->WriteLine("#error  generic field _" + Name() + " defaulted to no JSON support."); return true;
}
bool Element::isBasicType(const tsStringBase& baseType)
{
	for (auto type : UserDefinedBasicTypes())
	{
		if (baseType == type)
			return true;
	}

	if (baseType == "Enum" /*????*/ || baseType == "char" || baseType == "int8_t" || baseType == "int16_t" || baseType == "int32_t" || baseType == "int64_t" ||
		baseType == "bool" || baseType == "GUID")
	{
		return true;
	}
	return false;
}
tsStringBase Element::FullStructureName()
{
	if (!!NameSpace() /*&& usesSeparateClass()*/)
	{
		return NameSpace()->ToString() + _structureName;
	}
	return _structureName;
}
bool Element::WritePODStructure(std::shared_ptr<FileNode> files)
{
	for (auto& ele : Dependencies())
	{
		if (!ele->WritePODStructure(files))
			return false;
	}
	return true;
}
bool Element::WriteStructure(std::shared_ptr<FileNode> files)
{
	for (auto& ele : Dependencies())
	{
		if (!ele->WriteStructure(files))
			return false;
	}
	return true;
}
bool Element::WriteAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName)
{
	tsStringBase ns;

	if (!!NameSpace() /*&& usesSeparateClass()*/)
	{
		ns = NameSpace()->ToString();
	}

	//get_
	//set_
	//clear_
	if (ElementType() == "Null")
	{

	}
	else
	{
		if (IsOptional())
		{
			if (isBasicType(CppType()))
			{
				files->Header()->WriteLine(CppType() + " get_" + Name() + "() const { if (_" + Name() + "_exists) return _" + Name() + "; return " + Initializer() + "; }");
				files->Header()->WriteLine("bool exists_" + Name() + "() const { return _" + Name() + "_exists; }");
				files->Header()->WriteLine("void set_" + Name() + "(" + CppType() + " setTo = " + Initializer() + ") { _" + Name() + "_exists = true; _" + Name() + " = setTo; }");
			}
			else
			{
				if (usesSeparateClass())
				{
					files->Header()->WriteLine("const " + ns + PODStructureName() + "* get_" + Name() + "() const { if (_" + Name() + "_exists) return static_cast<const " + ns + PODStructureName() + "*>(&_" + Name() + "); return nullptr; }");
					files->Header()->WriteLine(ns + PODStructureName() + "* get_" + Name() + "() { if (_" + Name() + "_exists) return static_cast<" + ns + PODStructureName() + "*>(&_" + Name() + "); return nullptr; }");
					files->Header()->WriteLine("bool exists_" + Name() + "() const { return _" + Name() + "_exists; }");
					files->Header()->WriteLine("void set_" + Name() + "(const " + ns + PODStructureName() + "& setTo = " + ns + PODStructureName() + "()) { _" + Name() + "_exists = true; _" + Name() + " = setTo; }");
				}
				else
				{
					files->Header()->WriteLine("const " + CppType() + "* get_" + Name() + "() const { if (_" + Name() + "_exists) return &_" + Name() + "; return nullptr; }");
					files->Header()->WriteLine(CppType() + "* get_" + Name() + "() { if (_" + Name() + "_exists) return &_" + Name() + "; return nullptr; }");
					files->Header()->WriteLine("bool exists_" + Name() + "() const { return _" + Name() + "_exists; }");
					files->Header()->WriteLine("void set_" + Name() + "(const " + CppType() + "& setTo = " + CppType() + "()) { _" + Name() + "_exists = true; _" + Name() + " = setTo; }");
				}
			}
			files->Header()->WriteLine("void clear_" + Name() + "() { _" + Name() + "_exists = false; }");
		}
		else
		{
			if (isBasicType(CppType()))
			{
				files->Header()->WriteLine(CppType() + " get_" + Name() + "() const { return _" + Name() + "; }");
				files->Header()->WriteLine("void set_" + Name() + "(" + CppType() + " setTo) { _" + Name() + " = setTo; }");
				files->Header()->WriteLine("void clear_" + Name() + "() { _" + Name() + " = " + Initializer() + "; }");
			}
			else if (usesSeparateClass())
			{
				files->Header()->WriteLine("const " + ns + PODStructureName() + "& get_" + Name() + "() const { return _" + Name() + "; }");
				files->Header()->WriteLine(ns + PODStructureName() + "& get_" + Name() + "() { return _" + Name() + "; }");

				files->Header()->WriteLine("void set_" + Name() + "(const " + ns + PODStructureName() + "& setTo) { _" + Name() + " = setTo; }");

				files->Header()->WriteLine("void clear_" + Name() + "() { _" + Name() + ".clear(); }");
			}
			else
			{
				files->Header()->WriteLine("const " + CppType() + "& get_" + Name() + "() const { return _" + Name() + "; }");
				files->Header()->WriteLine(CppType() + "& get_" + Name() + "() { return _" + Name() + "; }");

				files->Header()->WriteLine("void set_" + Name() + "(const " + CppType() + "& setTo) { _" + Name() + " = setTo; }");
				if (ElementType() == "OID")
				{
					files->Header()->WriteLine("void set_" + Name() + "(const tscrypto::tsCryptoString& setTo) { _" + Name() + ".FromOIDString(setTo); }");
				}

				files->Header()->WriteLine("void clear_" + Name() + "() { _" + Name() + ".clear(); }");
			}
		}
		files->Header()->WriteLine();
		files->Source()->WriteLine();
	}
	return true;
}

std::shared_ptr<Namespace> Element::NameSpace()
{
	if (!!_namespace)
		return _namespace;

	std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

	while (!!node)
	{
		std::shared_ptr<NamespaceNode> nn = std::dynamic_pointer_cast<NamespaceNode>(node);

		if (!!nn)
		{
			_namespace = nn->CreateNamespace();
			return _namespace;
		}
		node = node->Parent().lock();
	}
	return std::shared_ptr<Namespace>(new RootNamespace());
}

std::shared_ptr<Element> Element::GetParentElement()
{
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();

	while (!!node)
	{
		std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(node);

		if (!!ele)
		{
			return ele;
		}
		node = node->Parent().lock();
	}
	return nullptr;
}

std::shared_ptr<SequenceNode> Element::ParentSequence()
{
	if (!!_parentSequence)
		return _parentSequence;

	std::shared_ptr<Element> ele = GetParentElement();

	while (!!ele && !(_parentSequence = std::dynamic_pointer_cast<SequenceNode>(ele)))
		ele = ele->GetParentElement();

	return _parentSequence;
}
std::shared_ptr<SequenceOfNode> Element::ParentSequenceOf()
{
	std::shared_ptr<SequenceOfNode> _parentSequenceOf;
	std::shared_ptr<Element> ele = GetParentElement();

	while (!!ele && !(_parentSequenceOf = std::dynamic_pointer_cast<SequenceOfNode>(ele)))
		ele = ele->GetParentElement();

	return _parentSequenceOf;
}
std::shared_ptr<ChoiceNode> Element::ParentChoice()
{
	std::shared_ptr<ChoiceNode> _parentChoice;
	std::shared_ptr<Element> ele = GetParentElement();

	while (!!ele && !(_parentChoice = std::dynamic_pointer_cast<ChoiceNode>(ele)))
		ele = ele->GetParentElement();

	return _parentChoice;
}
std::shared_ptr<NamespaceNode> Element::ParentNamespace()
{
	std::shared_ptr<Element> ele = GetParentElement();
	std::shared_ptr<NamespaceNode> ns;

	while (!!ele && !(ns = std::dynamic_pointer_cast<NamespaceNode>(ele)))
		ele = ele->GetParentElement();

	return ns;
}
std::shared_ptr<FileNode> Element::ParentFileNode()
{
	std::shared_ptr<Element> ele = GetParentElement();
	std::shared_ptr<FileNode> fn;

	while (!!ele && !(fn = std::dynamic_pointer_cast<FileNode>(ele)))
		ele = ele->GetParentElement();

	return fn;
}
std::shared_ptr<ElementContainer> Element::ParentContainer()
{
	if (!!_parentContainer)
		return _parentContainer;

	std::shared_ptr<tsXmlNode> ele = Parent().lock();

	while (!!ele && !(_parentContainer = std::dynamic_pointer_cast<ElementContainer>(ele)))
		ele = ele->Parent().lock();

	return _parentContainer;
}
std::shared_ptr<Element> Element::MatchingElement()
{
	if (!_matchingElement)
	{
		if (!!ParentSequence())
		{
			tsStringBase eleType = ElementType();
			tsStringBase eleType2;

			if (eleType == "ChoiceField" || eleType == "SequenceOfField")
				eleType2 = eleType;
			eleType.Replace("Field", "");

			for (auto ele : ParentSequence()->Elements())
			{
				if (ele->Name() == Name() && (ele->ElementType() == eleType || (eleType2.size() > 0 && ele->ElementType() == eleType2)))
				{
					_matchingElement = ele;
					break;
				}
			}
		}
	}
	return _matchingElement;
}

tsStringBase Element::BuildStructureName()
{
	tsStringBase tmp;

	if (StructureName().size() != 0)
		return StructureName();
	if (ElementType() == "Sequence" || ElementType() == "SequenceField")
		return Name();
	if (!!GetParentElement())
	{
		tmp = GetParentElement()->BuildStructureName();
	}
	if (tmp.size() > 0)
		tmp += "_";
	tmp += Name();
	return tmp;
}