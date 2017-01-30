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


#ifndef __RELATION_H__
#define __RELATION_H__

#pragma once

class Relation : public IObject
{
public:
	static std::shared_ptr<Relation> Create(std::shared_ptr<Schema> parent, std::shared_ptr<tsXmlNode> relationNode){ return IObject::Create<Relation>(parent, relationNode); }

	Relation(std::shared_ptr<Schema> parent, std::shared_ptr<tsXmlNode> relationNode);
	virtual ~Relation() {}

	std::shared_ptr<Schema> Parent() const { return _parent; }
	tsStringBase Name() const { return _Name; }
	tsStringBase ShortName() const { return _ShortName; }
	bool Persist() const { return _Persist; }
	bool ForceInTrigger() const { return _ForceInTrigger; }
	std::shared_ptr<::Table> Source() const { return _Source; }
	std::shared_ptr<::Table> Destination() const { return _Destination; }
	tsStringBase OneToManyName() const { return _OneToManyName; }
	tsStringBase ManyToOneName() const { return _ManyToOneName; }
	tsStringBase LoaderForMany() const { return _LoaderForMany; }
	tsStringBase LoaderForOne() const { return _LoaderForOne; }
	tsStringBase OneToOneSourceName() const { return _OneToOneSourceName; }
	tsStringBase OneToOneDestName() const { return _OneToOneDestName; }
	tsStringBase LoaderForDest() const { return _LoaderForDest; }
	const std::vector<std::shared_ptr<TableColumn> > SourceColumns() const { return _SourceColumns; }
	const std::vector<std::shared_ptr<TableColumn> > DestinationColumns() const { return _DestinationColumns; }

private:
	std::shared_ptr<Schema> _parent;
	tsStringBase _Name;
	tsStringBase _ShortName;
	bool _Persist;
	bool _ForceInTrigger;
	std::shared_ptr<::Table> _Source;
	std::shared_ptr<::Table> _Destination;
	tsStringBase _OneToManyName;
	tsStringBase _ManyToOneName;
	tsStringBase _LoaderForMany;
	tsStringBase _LoaderForOne;
	tsStringBase _OneToOneSourceName;
	tsStringBase _OneToOneDestName;
	tsStringBase _LoaderForDest;
	std::vector<std::shared_ptr<TableColumn> > _SourceColumns;
	std::vector<std::shared_ptr<TableColumn> > _DestinationColumns;

	void Parent(std::shared_ptr<Schema> parent) { _parent.reset(); _parent = parent; }
	void Name(const tsStringBase& setTo) { _Name = setTo; }
	void ShortName(const tsStringBase& setTo) { _ShortName = setTo; }
	void Persist(bool setTo) { _Persist = setTo; }
	void ForceInTrigger(bool setTo) { _ForceInTrigger = setTo; }
	void Source(std::shared_ptr<::Table> setTo) { _Source = setTo; }
	void Destination(std::shared_ptr<::Table> setTo) { _Destination = setTo; }
	void OneToManyName(const tsStringBase& setTo) { _OneToManyName = setTo; }
	void ManyToOneName(const tsStringBase& setTo) { _ManyToOneName = setTo; }
	void LoaderForMany(const tsStringBase& setTo) { _LoaderForMany = setTo; }
	void LoaderForOne(const tsStringBase& setTo) { _LoaderForOne = setTo; }
	void OneToOneSourceName(const tsStringBase& setTo) { _OneToOneSourceName = setTo; }
	void OneToOneDestName(const tsStringBase& setTo) { _OneToOneDestName = setTo; }
	void LoaderForDest(const tsStringBase& setTo) { _LoaderForDest = setTo; }
	void SourceColumns(std::vector<std::shared_ptr<TableColumn> > setTo) { _SourceColumns = setTo; }
	void DestinationColumns(std::vector<std::shared_ptr<TableColumn> > setTo) { _DestinationColumns = setTo; }
};

#endif // __RELATION_H__
