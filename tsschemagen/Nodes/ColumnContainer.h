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

#ifndef __COLUMNCONTAINER_H__
#define __COLUMNCONTAINER_H__

#pragma once

class TableColumn;
class Index;

class ColumnContainer : public IObject
{
public:
	//static std::shared_ptr<tsXmlNode> Create();

	ColumnContainer(std::shared_ptr<Schema> parent, std::shared_ptr<tsXmlNode> containerNode);
	virtual ~ColumnContainer() {}

	std::shared_ptr<IObject> Parent() const { return _parent; }
	tsStringBase Name() const { return _Name; }
	bool Persist() const { return _Persist; }
	const std::vector<std::shared_ptr<TableColumn> > Columns() const { return _Columns; }
	const std::vector<std::shared_ptr<Index> > Indexes() const { return _Indexes; }
	bool ReadOnly() const { return _ReadOnly; }
	tsStringBase JSONName() const { return _JSONName; }
	tsStringBase From() const { return _From; }
	tsStringBase description() const { return _Description; }


	std::shared_ptr<TableColumn> FindColumn(const tsStringBase& name);
	const std::vector<std::shared_ptr<Index> > PrimaryKeys();
	const std::vector<std::shared_ptr<Index> > NonPrimaryKeys();
	virtual void OnConstructionFinished();

protected:
	void ReadOnly(bool setTo) { _ReadOnly = setTo; }


private:
	std::shared_ptr<IObject> _parent;
	tsStringBase _Name;
	bool _Persist;
	std::vector<std::shared_ptr<TableColumn> > _Columns;
	std::vector<std::shared_ptr<Index> > _Indexes;
	bool _ReadOnly;
	tsStringBase _JSONName;
	tsStringBase _From;
	tsStringBase _Description;

	std::shared_ptr<tsXmlNode> _containerNode;

	void Parent(std::shared_ptr<IObject> parent) { _parent.reset(); _parent = parent; }
	void Name(const tsStringBase& setTo) { _Name = setTo; }
	void Persist(bool setTo) { _Persist = setTo; }
	void Columns(std::vector<std::shared_ptr<TableColumn> > setTo) { _Columns = setTo; }
	void Indexes(std::vector<std::shared_ptr<Index> > setTo) { _Indexes = setTo; }
	void JSONName(const tsStringBase& setTo) { _JSONName = setTo; }
	void From(const tsStringBase& setTo) { _From = setTo; }
	void description(const tsStringBase& setTo) { _Description = setTo; }
};

#endif // __COLUMNCONTAINER_H__
