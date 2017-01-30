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

#ifndef __INDEX_H__
#define __INDEX_H__

#pragma once

class Index : public IObject
{
public:
	static std::shared_ptr<Index> Create(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> columnNode){ return IObject::Create<Index>(parent, columnNode); }

	Index(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> indexNode);
	virtual ~Index() {}

	std::shared_ptr<ColumnContainer> Parent() const { return _parent; }
	tsStringBase Name() const { return _Name; }
	tsStringBase ShortName() const { return _ShortName; }
	tsStringBase SearchableName() const { return _SearchableName; }
	tsStringBase SearchClause() const { return _SearchClause; }
	tsStringBase DeleteSearchClause() const { return _DeleteSearchClause; }
	tsStringBase IndexType() const { return _IndexType; }
	bool LoadReturnsSingle() const { return _LoadReturnsSingle; }
	bool Deletable() const { return _Deletable; }
	const std::vector<std::shared_ptr<TableColumn> > Columns() const { return _Columns; }
	bool PrimaryKey() const { return IndexType() == "primary"; }
	bool UniqueKey() const { return IndexType() == "unique"; }
	bool SearchOnly() const { return IndexType() == "searchonly"; }
	tsStringBase description() const { return _Description; }


	std::shared_ptr<TableColumn> FindColumn(const tsStringBase& name);
	const std::vector<std::shared_ptr<Index> > PrimaryKeys();
	const std::vector<std::shared_ptr<Index> > NonPrimaryKeys();

private:
	std::shared_ptr<ColumnContainer> _parent;
	tsStringBase _Name;
	tsStringBase _ShortName;
	tsStringBase _SearchableName;
	tsStringBase _SearchClause;
	tsStringBase _DeleteSearchClause;
	tsStringBase _IndexType;
	bool _LoadReturnsSingle;
	bool _Deletable;
	std::vector<std::shared_ptr<TableColumn> > _Columns;
	tsStringBase _Description;


	void Parent(std::shared_ptr<ColumnContainer> parent) { _parent.reset(); _parent = parent; }
	void Name(const tsStringBase& setTo) { _Name = setTo; }
	void ShortName(const tsStringBase& setTo) { _ShortName = setTo; }
	void SearchableName(const tsStringBase& setTo) { _SearchableName = setTo; }
	void SearchClause(const tsStringBase& setTo) { _SearchClause = setTo; }
	void DeleteSearchClause(const tsStringBase& setTo) { _DeleteSearchClause = setTo; }
	void IndexType(const tsStringBase& setTo) { _IndexType = setTo; }
	void LoadReturnsSingle(bool setTo) { _LoadReturnsSingle = setTo; }
	void Deletable(bool setTo) { _Deletable = setTo; }
	void Columns(std::vector<std::shared_ptr<TableColumn> > setTo) { _Columns = setTo; }
	void description(const tsStringBase& setTo) { _Description = setTo; }

};

#endif // __INDEX_H__
