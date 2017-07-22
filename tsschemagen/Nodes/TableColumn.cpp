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


#include "stdafx.h"

TableColumn::TableColumn(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> columnNode)
{
	tsStringBase tmp;

	Parent(parent);
	Name(columnNode->Attributes().item("Name"));
	ShortName(columnNode->Attributes().item("ShortName"));
	JSONName(columnNode->Attributes().item("JSONName"));
	Nullable(columnNode->Attributes().itemAsBoolean("Nullable", false));
	JSONUseDecrypted(columnNode->Attributes().itemAsBoolean("JSONUseDecrypted", false));
	FieldType(columnNode->Attributes().item("Type"));
	FieldLength(columnNode->Attributes().itemAsNumber("Length", 0));
	UnencryptedObject(columnNode->Attributes().item("Object"));
	EncryptedObject(columnNode->Attributes().item("EncryptedObject"));
	EncryptionOIDCode(columnNode->Attributes().item("EncryptionOID"));
	DefaultGenerator(columnNode->Attributes().item("DefGen"));
	Default(columnNode->Attributes().item("Default"));
	Table(columnNode->Attributes().item("Table"));
	Formula(columnNode->Attributes().item("Formula"));
	tmp = (columnNode->Attributes().item("JSONMergeType"));
	tmp.ToLower();

	if (tmp == "combine")
		JSONMergeType(jmt_Combine);
	else if (tmp == "overwrite")
		JSONMergeType(jmt_Overwrite);
	else if (tmp == "subobject")
		JSONMergeType(jmt_SubObject);
	else
		JSONMergeType(jmt_SubObject);

	Alias(columnNode->Attributes().item("Alias"));
	if (Alias().size() > 0)
		AliasFieldname(Alias());
	else
		AliasFieldname(Name());
	description(columnNode->Attributes().item("descripton"));
}

void TableColumn::GetColumnNodeParameters(tsStringBase& ConstPart, tsStringBase& TypePart, tsStringBase& RightPart)
{
	ConstPart = "";
	TypePart = "";
	RightPart = "";

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		TypePart = "tscrypto::tsCryptoString";
		ConstPart = "const ";
		RightPart = "& ";
	}
	else if (FieldType() == "System.Guid")
	{
		TypePart = "GUID";
		ConstPart = "const ";
		RightPart = "& ";
	}
	else if (FieldType() == "System.Boolean")
	{
		TypePart = "bool";
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
		TypePart = "int";
	}
	else if (FieldType() == "System.DateTime")
	{
		TypePart = "tscrypto::tsCryptoDate";
		ConstPart = "const ";
		RightPart = "& ";
	}
	else if (FieldType() == "System.Double")
	{
		TypePart = "double";
	}
	else
	{
		TypePart = "tscrypto::tsCryptoString";
		ConstPart = "const ";
		RightPart = "& ";
	}
}
tsStringBase TableColumn::FullName() const
{
    if (!Formula().empty())
    {
        return Formula();
    }
    if (Table().empty())
    {
        return Name();
    }
    return Table() + "." + Name();
}
void TableColumn::Get_C_ColumnNodeParameters(tsStringBase& ConstPart, tsStringBase& TypePart, tsStringBase& RightPart, uint32_t& arraySize)
{
	ConstPart = "";
	TypePart = "";
	RightPart = "";
    arraySize = 0;

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		TypePart = "char";
		ConstPart = "const ";
		RightPart = "* ";
        arraySize = FieldLength();
	}
	else if (FieldType() == "System.Guid")
	{
		TypePart = "GUID";
		ConstPart = "const ";
		RightPart = "* ";
	}
	else if (FieldType() == "System.Boolean")
	{
		TypePart = "ts_bool";
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
		TypePart = "int";
	}
	else if (FieldType() == "System.DateTime")
	{
		TypePart = "char";
        arraySize = 15;
	}
	else if (FieldType() == "System.Double")
	{
		TypePart = "double";
	}
	else
	{
		TypePart = "char";
		ConstPart = "const ";
		RightPart = "* ";
        arraySize = FieldLength();
    }
}
tsStringBase TableColumn::GetTSFieldType()
{
	tsStringBase type = "TSFieldDefinition::";

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		type += "ftString";
	}
	else if (FieldType() == "System.Guid")
	{
		type += "ftGUID";
	}
	else if (FieldType() == "System.Boolean")
	{
		type += "ftBool";
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
		type += "ftLong";
	}
	else if (FieldType() == "System.DateTime")
	{
		type += "ftDate";
	}
	else if (FieldType() == "System.Double")
	{
		type += "ftDouble";
	}
	else
	{
		type += "ftString";
	}
	return type;
}
tsStringBase TableColumn::Get_C_TSFieldType()
{
    tsStringBase type = "dbr";

    if (FieldType() == "System.String" || FieldType() == "System.Char[]")
    {
        type += "ftString";
    }
    else if (FieldType() == "System.Guid")
    {
        type += "ftGUID";
    }
    else if (FieldType() == "System.Boolean")
    {
        type += "ftBool";
    }
    else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
    {
        type += "ftLong";
    }
    else if (FieldType() == "System.DateTime")
    {
        type += "ftDate";
    }
    else if (FieldType() == "System.Double")
    {
        type += "ftDouble";
    }
    else
    {
        type += "ftString";
    }
    return type;
}
tsStringBase TableColumn::Get_C_ToSqlName()
{
    tsStringBase type;

    if (FieldType() == "System.String" || FieldType() == "System.Char[]")
    {
        type += "StringToSql";
    }
    else if (FieldType() == "System.Guid")
    {
        type += "GUIDToSql";
    }
    else if (FieldType() == "System.Boolean")
    {
        type += "BoolToSql";
    }
    else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
    {
        type += "LongToSql";
    }
    else if (FieldType() == "System.DateTime")
    {
        type += "DateToSql";
    }
    else if (FieldType() == "System.Double")
    {
        type += "DoubleToSql";
    }
    else
    {
        type += "StringToSql";
    }
    return type;
}
tsStringBase TableColumn::Get_C_FromSqlName()
{
    tsStringBase type;

    if (FieldType() == "System.String" || FieldType() == "System.Char[]")
    {
        type += "_populateStringField";
    }
    else if (FieldType() == "System.Guid")
    {
        type += "_populateGUIDField";
    }
    else if (FieldType() == "System.Boolean")
    {
        type += "_populateBoolField";
    }
    else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
    {
        type += "_populateLongField";
    }
    else if (FieldType() == "System.DateTime")
    {
        type += "_populateDateField";
    }
    else if (FieldType() == "System.Double")
    {
        type += "_populateDoubleField";
    }
    else
    {
        type += "_populateStringField";
    }
    return type;
}

tsStringBase TableColumn::GetConstPart()
{
	tsStringBase ConstPart = "";

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		ConstPart = "const ";
	}
	else if (FieldType() == "System.Guid")
	{
		ConstPart = "const ";
	}
	else if (FieldType() == "System.Boolean")
	{
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
	}
	else if (FieldType() == "System.DateTime")
	{
		ConstPart = "const ";
	}
	else if (FieldType() == "System.Double")
	{
	}
	else
	{
		ConstPart = "const ";
	}
	return ConstPart;
}
tsStringBase TableColumn::GetTypePart()
{
	tsStringBase TypePart = "";

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		TypePart = "tscrypto::tsCryptoString";
	}
	else if (FieldType() == "System.Guid")
	{
		TypePart = "GUID";
	}
	else if (FieldType() == "System.Boolean")
	{
		TypePart = "bool";
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
		TypePart = "int";
	}
	else if (FieldType() == "System.DateTime")
	{
		TypePart = "tscrypto::tsCryptoDate";
	}
	else if (FieldType() == "System.Double")
	{
		TypePart = "double";
	}
	else
	{
		TypePart = "tscrypto::tsCryptoString";
	}
	return TypePart;
}
tsStringBase TableColumn::GetRightPart()
{
	tsStringBase RightPart = "";

	if (FieldType() == "System.String" || FieldType() == "System.Char[]")
	{
		RightPart = "& ";
	}
	else if (FieldType() == "System.Guid")
	{
		RightPart = "& ";
	}
	else if (FieldType() == "System.Boolean")
	{
	}
	else if (FieldType() == "System.Int32" || FieldType() == "System.Int16")
	{
	}
	else if (FieldType() == "System.DateTime")
	{
		RightPart = "& ";
	}
	else if (FieldType() == "System.Double")
	{
	}
	else
	{
		RightPart = "& ";
	}
	return RightPart;
}

