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


#ifndef __TABLECOLUMN_H__
#define __TABLECOLUMN_H__

#pragma once

typedef enum
{
	jmt_Combine,
	jmt_Overwrite,
	jmt_SubObject
} JSON_MergeType;

class TableColumn : public IObject
{
public:
	static std::shared_ptr<TableColumn> Create(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> columnNode){ return IObject::Create<TableColumn>(parent, columnNode); }

	TableColumn(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> columnNode);
	virtual ~TableColumn() {}

	std::shared_ptr<ColumnContainer> Parent() const { return _parent; }
	tsStringBase Name() const { return _Name; }
	tsStringBase ShortName() const { return _ShortName; }
	tsStringBase JSONName() const { return _JSONName; }
	bool Nullable() const { return _IsNullable; }
	bool JSONUseDecrypted() const { return _JSONUseDecrypted; }
	tsStringBase FieldType() const { return _FieldType; }
	int FieldLength() const { return _FieldLength; }
	tsStringBase UnencryptedObject() const { return _UnencryptedObject; }
	tsStringBase EncryptedObject() const { return _EncryptedObject; }
	tsStringBase EncryptionOIDCode() const { return _EncryptionOIDCode; }
	tsStringBase DefaultGenerator() const { return _DefaultGenerator; }
	tsStringBase Default() const { return _Default; }
	tsStringBase Table() const { return _Table; }
	tsStringBase Alias() const { return _Alias; }
	tsStringBase AliasFieldname() const { return _AliasFieldname; }
	tsStringBase Formula() const { return _Formula; }
	JSON_MergeType JSONMergeType() const { return _JSONMergeType; }
	tsStringBase description() const { return _Description; }


	void GetColumnNodeParameters(tsStringBase& ConstPart, tsStringBase& TypePart, tsStringBase& RightPart);
	tsStringBase GetTSFieldType();
	tsStringBase GetConstPart();
	tsStringBase GetTypePart();
	tsStringBase GetRightPart();

private:
	std::shared_ptr<ColumnContainer> _parent;
	tsStringBase _Name;
	tsStringBase _ShortName;
	tsStringBase _JSONName;
	bool _IsNullable;
	bool _JSONUseDecrypted;
	tsStringBase _FieldType;
	int _FieldLength;
	tsStringBase _UnencryptedObject;
	tsStringBase _EncryptedObject;
	tsStringBase _EncryptionOIDCode;
	tsStringBase _DefaultGenerator;
	tsStringBase _Default;
	tsStringBase _Table;
	tsStringBase _Alias;
	tsStringBase _AliasFieldname;
	tsStringBase _Formula;
	JSON_MergeType _JSONMergeType;
	tsStringBase _Description;


	void Parent(std::shared_ptr<ColumnContainer> parent) { _parent.reset(); _parent = parent; }
	void Name(const tsStringBase& setTo) { _Name = setTo; }
	void ShortName(const tsStringBase& setTo) { _ShortName = setTo; }
	void JSONName(const tsStringBase& setTo) { _JSONName = setTo; }
	void Nullable(bool setTo) { _IsNullable = setTo; }
	void JSONUseDecrypted(bool setTo) { _JSONUseDecrypted = setTo; }
	void FieldType(const tsStringBase& setTo) { _FieldType = setTo; }
	void FieldLength(int setTo) { _FieldLength = setTo; }
	void UnencryptedObject(const tsStringBase& setTo) { _UnencryptedObject = setTo; }
	void EncryptedObject(const tsStringBase& setTo) { _EncryptedObject = setTo; }
	void EncryptionOIDCode(const tsStringBase& setTo) { _EncryptionOIDCode = setTo; }
	void DefaultGenerator(const tsStringBase& setTo) { _DefaultGenerator = setTo; }
	void Default(const tsStringBase& setTo) { _Default = setTo; }
	void Table(const tsStringBase& setTo) { _Table = setTo; }
	void Alias(const tsStringBase& setTo) { _Alias = setTo; }
	void AliasFieldname(const tsStringBase& setTo) { _AliasFieldname = setTo; }
	void Formula(const tsStringBase& setTo) { _Formula = setTo; }
	void JSONMergeType(JSON_MergeType setTo) { _JSONMergeType = setTo; }
	void description(const tsStringBase& setTo) { _Description = setTo; }
};

#endif // __TABLECOLUMN_H__
