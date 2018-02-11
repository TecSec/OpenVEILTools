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

#define MemAllocSize 100

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif // MIN

const tsStringBase::size_type tsStringBase::npos = (size_type)(-1);

tsStringBase::tsStringBase() :
	_data(tsCreateBuffer())
{
};
tsStringBase::tsStringBase(std::initializer_list<value_type> init) :
	_data(tsCreateBuffer())
{
	tsStringBase::size_type index = 0;
    char* ptr;

	resize(init.size());

    ptr = rawData();
	for (auto i = init.begin(); i != init.end(); ++i)
	{
		ptr[index++] = *i;
	}
}
tsStringBase::tsStringBase(tsStringBase &&obj) :
	_data(tsCreateBuffer())
{
    tsMoveBuffer(obj._data, _data);
}
tsStringBase::tsStringBase(const_pointer data, tsStringBase::size_type Len) :_data(tsCreateBuffer())
{
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(rawData(), data, Len * sizeof(data[0]));
	}
};
tsStringBase::tsStringBase(const tsStringBase &obj) :_data(tsCreateBuffer())
{
	copyFrom(obj);
};
tsStringBase::tsStringBase(const_pointer data) :_data(tsCreateBuffer())
{
	tsStringBase::size_type Len = 0;
	if (data != nullptr)
	{
		Len = strlen(data);
	}
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(rawData(), data, Len * sizeof(value_type));
	}
}
tsStringBase::tsStringBase(value_type data, tsStringBase::size_type numChars) :_data(tsCreateBuffer())
{
	resize(numChars, data);
}
tsStringBase::~tsStringBase()
{
    tsFreeBuffer(&_data);
};
//tsStringBase::operator LPCTSTR ()
//{
//	return c_str();
//}
tsStringBase &tsStringBase::operator= (tsStringBase &&obj)
{
	if (&obj != this)
	{
        tsEmptyBuffer(_data);
        tsMoveBuffer(obj._data, _data);
	}
	return *this;
}
tsStringBase &tsStringBase::operator= (const tsStringBase &obj)
{
	copyFrom(obj);
	return *this;
}

tsStringBase &tsStringBase::operator= (const_pointer data) /* zero terminated */
{
	return (*this) = (tsStringBase(data));
}
tsStringBase &tsStringBase::operator= (value_type data)
{
	resize(1);
	rawData()[0] = data;
	return *this;
}
tsStringBase &tsStringBase::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsStringBase &tsStringBase::operator+= (const tsStringBase &obj)
{
    tsAppendStringLenToBuffer(_data, obj.c_str(), (uint32_t)obj.size());
	return *this;
}
tsStringBase &tsStringBase::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsStringBase(data);
}
tsStringBase &tsStringBase::operator+= (value_type data)
{
    tsAppendStringLenToBuffer(_data, &data, 1);
	return *this;
}
tsStringBase &tsStringBase::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}
int tsStringBase::compare(const tsStringBase& str) const
{
	size_type count = MIN(size(), str.size());
	int diff = 0;

	diff = memcmp(c_str(), str.c_str(), count);
	if (diff != 0)
		return diff;
	if (size() > str.size())
		return 1;
	if (size() < str.size())
		return -1;
	return 0;
}
int tsStringBase::compare(size_type pos1, size_type count1, const tsStringBase& str) const
{
	return substr(pos1, count1).compare(str);
}
int tsStringBase::compare(size_type pos1, size_type count1, const tsStringBase& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int tsStringBase::compare(const_pointer s) const
{
	size_type len = strlen(s);
	size_type count = MIN(size(), len);
	int diff = 0;

	diff = memcmp(c_str(), s, count);
	if (diff != 0)
		return diff;

	if (size() > len)
		return 1;
	if (size() < len)
		return -1;
	return 0;
}
int tsStringBase::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int tsStringBase::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(tsStringBase(s, count2));
}
tsStringBase::size_type tsStringBase::size() const
{
	return tsBufferUsed(_data);
}
tsStringBase::size_type tsStringBase::length() const
{
	return size();
}
void tsStringBase::clear()
{
	resize(0);
}
_Post_satisfies_(this->m_data != nullptr) void tsStringBase::reserve(tsStringBase::size_type newSize)
{
    tsReserveBuffer(_data, (uint32_t)newSize);
}
tsStringBase::size_type tsStringBase::capacity() const
{
	return tsBufferReserved(_data);
}
tsStringBase::size_type tsStringBase::max_size() const
{
	return 0x7FFFFFFF;
}
_Post_satisfies_(this->m_data != nullptr) void tsStringBase::resize(tsStringBase::size_type newSize)
{
	resize(newSize, (value_type)0);
}
_Post_satisfies_(this->m_data != nullptr) void tsStringBase::resize(tsStringBase::size_type newSize, value_type value)
{
    uint32_t oldSize = (uint32_t)size();

	if (!tsResizeBuffer(_data, (uint32_t)newSize))
		throw std::bad_alloc();

	if (newSize > oldSize)
	{
		memset(&rawData()[oldSize], value, newSize - oldSize);
	}
}
tsStringBase::reference tsStringBase::at(tsStringBase::size_type index)
{
	if (index >= size())
	{
		throw std::out_of_range("index");
	}
	return rawData()[index];
}
tsStringBase::const_reference tsStringBase::at(tsStringBase::size_type index) const
{
	if (index >= size())
	{
		throw std::out_of_range("index");
	}
	return c_str()[index];
}
tsStringBase::value_type tsStringBase::c_at(tsStringBase::size_type index) const
{
	if (index >= size())
	{
		throw std::out_of_range("index");
	}
	return c_str()[index];
}
//
// used to access the buffer directly.
// In all cases this will return a buffer for this class instance only.
//
// NOTE:  Do not access data beyond size() characters
//
tsStringBase::pointer tsStringBase::data()
{
	return rawData();
}
tsStringBase::const_pointer tsStringBase::data() const
{
	return c_str();
}
tsStringBase::reference tsStringBase::front()
{
	return rawData()[0];
}
tsStringBase::const_reference tsStringBase::front() const
{
	return c_str()[0];
}
tsStringBase::reference tsStringBase::back()
{
	if (empty())
		throw std::out_of_range("index");
	return rawData()[size() - 1];
}
tsStringBase::const_reference tsStringBase::back() const
{
	if (empty())
		throw std::out_of_range("index");
	return c_str()[size() - 1];
}
bool tsStringBase::empty() const
{
	return size() == 0;
}
tsStringBase::const_pointer tsStringBase::c_str() const
{
	return (tsStringBase::const_pointer)tsGetBufferDataPtr(_data);
}
void tsStringBase::push_back(value_type ch)
{
	resize(size() + 1, ch);
}
void tsStringBase::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}
tsStringBase::reference tsStringBase::operator [] (tsStringBase::size_type index)
{
	return at(index);
}
tsStringBase::const_reference tsStringBase::operator [] (tsStringBase::size_type index) const
{
	return at(index);
}
tsStringBase &tsStringBase::assign(tsStringBase::size_type size, tsStringBase::value_type ch)
{
	clear();
	resize(size, ch);
	return *this;
}
tsStringBase &tsStringBase::assign(const tsStringBase &obj)
{
	*this = obj;
	return *this;
}
tsStringBase &tsStringBase::assign(const tsStringBase &obj, tsStringBase::size_type pos, tsStringBase::size_type count)
{
	*this = obj.substr(pos, count);
	return *this;
}
tsStringBase &tsStringBase::assign(tsStringBase &&obj)
{
	*this = std::move(obj);
	return *this;
}
tsStringBase &tsStringBase::assign(const_pointer newData, tsStringBase::size_type size)
{
	resize(size);
	if (size > 0 && newData != nullptr)
	{
		memcpy(rawData(), newData, size * sizeof(value_type));
	}
	return *this;
}
tsStringBase &tsStringBase::assign(std::initializer_list<value_type> iList)
{
	size_type pos = size();
    pointer ptr;

	resize(iList.size());
    ptr = rawData();
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		ptr[pos++] = *it;
	}
	return *this;
}
tsStringBase::size_type tsStringBase::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw std::out_of_range("index");
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &c_str()[pos], sizeof(value_type) * count);
	return count;
}
void tsStringBase::copyFrom(const tsStringBase &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(rawData(), obj.c_str(), size() * sizeof(value_type));
}
void tsStringBase::swap(tsStringBase &obj)
{
	std::swap(_data, obj._data);
}
tsStringBase &tsStringBase::prepend(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsStringBase(data));
}
tsStringBase &tsStringBase::prepend(const_pointer data, tsStringBase::size_type len)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsStringBase(data, len));
}
tsStringBase &tsStringBase::prepend(value_type data)
{
    tsPrependStringLenToBuffer(_data, &data, 1);
	return *this;
}
tsStringBase &tsStringBase::prepend(uint8_t data)
{
    tsPrependBuffer(_data, &data, 1);
	return *this;
}
tsStringBase &tsStringBase::prepend(const tsStringBase &obj)
{
    tsPrependStringLenToBuffer(_data, obj.c_str(), (uint32_t)obj.size());
	return *this;
}
tsStringBase &tsStringBase::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
tsStringBase &tsStringBase::append(const tsStringBase &obj)
{
    tsAppendStringLenToBuffer(_data, obj.c_str(), (uint32_t)obj.size());
	return *this;
}
tsStringBase &tsStringBase::append(const tsStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsStringBase &tsStringBase::append(const_pointer data, size_type len)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsStringBase(data, len));
}
tsStringBase &tsStringBase::append(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsStringBase(data));
}
tsStringBase &tsStringBase::append(std::initializer_list<value_type> list)
{
	size_type pos = size();
    pointer ptr;

	resize(size() + list.size());
    ptr = rawData();
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		ptr[pos++] = *it;
	}
	return *this;
}
tsStringBase &tsStringBase::append(value_type data)
{
    tsAppendStringLenToBuffer(_data, &data, 1);
	return *this;
}
tsStringBase &tsStringBase::append(uint8_t data)
{
	tsStringBase buffer;

	buffer.Format("%d", data);
	append(buffer);
	return *this;
}
//tsStringBase &tsStringBase::append(int8_t val)
//{
//	tsStringBase buffer;
//
//	buffer.Format("%d", val);
//	append(buffer);
//return *this;
//}
tsStringBase &tsStringBase::append(int16_t val)
{
	tsStringBase buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
tsStringBase &tsStringBase::append(int32_t val)
{
	tsStringBase buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
#ifdef _MSC_VER
tsStringBase &tsStringBase::append(long val)
{
	tsStringBase buffer;

	buffer.Format("%ld", val);
	append(buffer);
	return *this;
}
tsStringBase &tsStringBase::append(unsigned long val)
{
	tsStringBase buffer;

	buffer.Format("%lu", val);
	append(buffer);
	return *this;
}
#endif
tsStringBase &tsStringBase::append(int64_t val)
{
	tsStringBase buffer;

	buffer.Format("%lld", val);
	append(buffer);
	return *this;
}
//tsStringBase &tsStringBase::append(uint8_t val)
//{
//	tsStringBase buffer;
//
//	buffer.Format("%u", val);
//	append(buffer);
//return *this;
//}
tsStringBase &tsStringBase::append(uint16_t val)
{
	tsStringBase buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsStringBase &tsStringBase::append(uint32_t val)
{
	tsStringBase buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsStringBase &tsStringBase::append(uint64_t val)
{
	tsStringBase buffer;

	buffer.Format("%llu", val);
	append(buffer);
	return *this;
}

tsStringBase& tsStringBase::erase(tsStringBase::size_type pos, tsStringBase::size_type count)
{
	if (pos > size())
		throw std::out_of_range("index");
    if (!tsEraseFromBuffer(_data, (uint32_t)pos, (uint32_t)count))
        throw std::out_of_range("index");
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::size_type count, tsStringBase::value_type ch)
{
	size_type oldsize = size();
    pointer ptr;

	resize(size() + count);
    ptr = rawData();
	memmove(&ptr[index + count], &ptr[index], sizeof(value_type) * (oldsize - index));
	memset(&ptr[index], ch, count);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::value_type ch)
{
    tsInsertIntoBuffer(_data, (uint32_t)index, (const uint8_t*)&ch, 1);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::const_pointer s)
{
	if (s == nullptr || !tsInsertIntoBuffer(_data, (uint32_t)index, (const uint8_t*)s, tsStrLen(s)))
		throw std::invalid_argument("s is NULL");
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::const_pointer s, tsStringBase::size_type count)
{
	if (s == nullptr || !tsInsertIntoBuffer(_data, (uint32_t)index, (const uint8_t*)s, (uint32_t)count))
		throw std::invalid_argument("s is NULL");
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, const tsStringBase& str)
{
	if (!tsInsertIntoBuffer(_data, (uint32_t)index, (const uint8_t*)str.c_str(), (uint32_t)str.size()))
		return *this;
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, const tsStringBase& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsStringBase& tsStringBase::insert(size_type pos, std::initializer_list<value_type> iList)
{
	size_type oldsize = size();
    pointer ptr;

	if (pos >= size())
	{
		append(iList);
		return *this;
	}
	resize(size() + iList.size());
    ptr = rawData();
	memmove(&ptr[pos + iList.size()], &ptr[pos], sizeof(value_type) * (oldsize - pos));
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		ptr[pos++] = *it;
	}
	return *this;

}

//bool tsStringBase::LoadString(long ID, HINSTANCE hInstance)
//{
//	long retVal;
//	long oldSize;
//
//	if ( resize(1024) != 1024 )
//	{
//		clear();
//		return false;
//	}
//
//	retVal = ::LoadString(hInstance, ID, m_data, m_used + 1);
//	while ( retVal == m_used || retVal == m_used + 1 )
//	{
//		oldSize = m_used;
//		if ( resize(m_used + 1024) != oldSize + 1024 )
//		{
//			clear();
//			return false;
//		}
//		retVal = ::LoadString(hInstance, ID, m_data, m_used + 1);
//	}
//	if ( retVal == 0 )
//	{
//		clear();
//		return false;
//	}
//	resize(retVal);
//	return true;
//}
tsStringBase &tsStringBase::InsertAt(tsStringBase::size_type offset, value_type value)
{
	return InsertAt(offset, &value, 1);
}
tsStringBase &tsStringBase::InsertAt(tsStringBase::size_type offset, const_pointer value, int32_t len)
{
	if (len == -1)
		return InsertAt(offset, tsStringBase(value));
	return InsertAt(offset, tsStringBase(value, len));
}

tsStringBase &tsStringBase::InsertAt(tsStringBase::size_type offset, const tsStringBase &value)
{
    tsInsertIntoBuffer(_data, (uint32_t)offset, (const uint8_t*)value.c_str(), (uint32_t)value.size());
	return *this;
}

tsStringBase &tsStringBase::DeleteAt(tsStringBase::size_type offset, tsStringBase::size_type count)
{
    tsEraseFromBuffer(_data, (uint32_t)offset, (uint32_t)count);
	return *this;
}
tsStringBase& tsStringBase::replace(size_type pos, size_type count, const tsStringBase& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsStringBase& tsStringBase::replace(size_type pos, size_type count, const tsStringBase& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsStringBase& tsStringBase::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsStringBase& tsStringBase::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsStringBase& tsStringBase::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsStringBase &tsStringBase::Replace(tsStringBase::size_type i_Begin, tsStringBase::size_type i_End, const_pointer i_newData, int32_t i_newDataLength)
{
	tsStringBase::size_type repLen;

	if (i_Begin > i_End || i_newData == nullptr)
		return *this;

	if (i_newDataLength == -1)
	{
		repLen = strlen(i_newData);
	}
	else
	{
		repLen = i_newDataLength;
	}
	if (i_Begin >= size())
		return *this;
	if (i_End >= size())
		i_End = size() - 1;

	if (!(DeleteAt(i_Begin, i_End - i_Begin + 1).c_str()))
		return *this;

	return InsertAt(i_Begin, i_newData, (int32_t)repLen);
}
tsStringBase &tsStringBase::Replace(const_pointer find, const_pointer replacement, int32_t count)
{
	return Replace(tsStringBase(find), tsStringBase(replacement), count);
}

tsStringBase &tsStringBase::Replace(const tsStringBase &find, const tsStringBase &replacement, int32_t count)
{
	tsStringBase::size_type posi;
	tsStringBase::size_type findLen;
	tsStringBase::size_type repLen;

	findLen = find.size();
	repLen = replacement.size();
	if (findLen < 1 || findLen > size())
		return *this;
	if (count == -1)
		count = (int32_t)max_size();
	posi = 0;
	while (posi + findLen <= size() && count > 0)
	{
        pointer ptr = rawData();
		if (strncmp(&ptr[posi], find.c_str(), findLen) == 0)
		{
			count--;
			if (findLen == repLen)
			{
				memcpy(&ptr[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else if (findLen < repLen)
			{
				tsStringBase::size_type oldLen = size();

				resize(oldLen + repLen - findLen);
                ptr = rawData();
				if (oldLen - findLen > posi)
					memmove(&ptr[posi + repLen], &ptr[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				memcpy(&ptr[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else
			{
				tsStringBase::size_type oldLen = size();

				if (oldLen - findLen > posi)
				{
					memmove(&ptr[posi + repLen], &ptr[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				}
				if (repLen > 0)
					memcpy(&ptr[posi], replacement.c_str(), repLen * sizeof(value_type));
				resize(oldLen + repLen - findLen);
				posi += repLen - 1;
			}
		}
		posi++;
	}
	return *this;
}
tsStringBase::size_type tsStringBase::find(const tsStringBase& str, size_type pos) const
{
	tsStringBase::size_type i;
	tsStringBase::size_type len = 0;
    const_pointer ptr;

	len = str.size();
	if (len == 0)
		return npos;

	if (pos + len > size())
		return npos;
    ptr = c_str();
	for (i = pos; i < size() - len + 1; i++)
	{
		const_pointer in_data_c_str = str.c_str();
		if (memcmp(in_data_c_str, &ptr[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	tsStringBase::size_type i;
    const_pointer ptr;

	if (count == 0)
		return npos;

	if (pos + count > size())
		return npos;
    ptr = c_str();
    for (i = pos; i < size() - count + 1; i++)
	{
		if (memcmp(s, &ptr[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	tsStringBase::size_type i;
	tsStringBase::size_type len;
    const_pointer ptr = c_str();

	len = strlen(s);
	if (len == 0)
		return npos;
	if (pos + len > size())
		return npos;
	for (i = pos; i < size() - len + 1; i++)
	{
		if (memcmp(s, &ptr[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find(value_type ch, size_type pos) const
{
	tsStringBase::size_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		return npos;
	for (i = pos; i < size(); i++)
	{
		if (ptr[i] == ch)
		{
			return i;
		}
	}
	return npos;
}

tsStringBase::size_type tsStringBase::rfind(const tsStringBase& str, size_type pos) const
{
	size_type count = str.size();
    const_pointer ptr = c_str();

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(str.c_str(), &ptr[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::rfind(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;
    const_pointer ptr = c_str();

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(s, &ptr[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	size_type count = strlen(s);
	if (count == 0)
		return npos;

	return rfind(s, pos, count);
}
tsStringBase::size_type tsStringBase::rfind(value_type ch, size_type pos) const
{
	if (pos >= size())
		pos = size() - 1;

	difference_type i;
    const_pointer ptr = c_str();

	for (i = pos; i >= 0; i--)
	{
		if (ptr[i] == ch)
		{
			return i;
		}
	}
	return npos;
}

tsStringBase::size_type tsStringBase::find_first_of(const tsStringBase& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
tsStringBase::size_type tsStringBase::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsStringBase::size_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		return npos;

	for (i = pos; i < size(); i++)
	{
		if (memchr(s, ptr[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, strlen(s));
}
tsStringBase::size_type tsStringBase::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}

tsStringBase::size_type tsStringBase::find_first_not_of(const tsStringBase& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
tsStringBase::size_type tsStringBase::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsStringBase::size_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		return npos;

	for (i = pos; i < size(); i++)
	{
		if (memchr(s, ptr[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, strlen(s));
}
tsStringBase::size_type tsStringBase::find_first_not_of(value_type ch, size_type pos) const
{
	tsStringBase::size_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		return npos;

	for (i = pos; i < size(); i++)
	{
		if (ptr[i] != ch)
		{
			return i;
		}
	}
	return npos;
}

tsStringBase::size_type tsStringBase::find_last_of(const tsStringBase& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
tsStringBase::size_type tsStringBase::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsStringBase::difference_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, ptr[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, strlen(s));
}
tsStringBase::size_type tsStringBase::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}

tsStringBase::size_type tsStringBase::find_last_not_of(const tsStringBase& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
tsStringBase::size_type tsStringBase::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsStringBase::difference_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, ptr[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, strlen(s));
}
tsStringBase::size_type tsStringBase::find_last_not_of(value_type ch, size_type pos) const
{
	tsStringBase::difference_type i;
    const_pointer ptr = c_str();

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (ptr[i] != ch)
		{
			return i;
		}
	}
	return npos;
}



tsStringBase &tsStringBase::Format(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	resize(0);
	resize(10240);
	#ifdef _MSC_VER
	vsnprintf_s(data(), size(), size(), msg, args);
	#else
	vsnprintf(data(), size(), msg, args);
	#endif
	resize(strlen(c_str()));
	va_end(args);
	return *this;
}

tsStringBase &tsStringBase::Format(tsStringBase msg, ...)
{
	va_list args;

	va_start(args, msg);
	resize(0);
	resize(10240);
	#ifdef _MSC_VER
	vsnprintf_s(data(), size(), size(), msg.c_str(), args);
	#else
	vsnprintf(data(), size(), msg.c_str(), args);
	#endif
	resize(strlen(c_str()));
	va_end(args);
	return *this;
}

tsStringBase &tsStringBase::FormatArg(const char *msg, va_list arg)
{
	resize(0);
	resize(10240);
	#ifdef _MSWC_VER
	vsnprintf_s(data(), size(), size(), msg, arg);
	#else
	vsnprintf(data(), size(), msg, arg);
	#endif
	resize(strlen(c_str()));
	return *this;
}

tsStringBase &tsStringBase::FormatArg(const tsStringBase& msg, va_list arg)
{
	resize(0);
	resize(10240);
	#ifdef _MSC_VER
	vsnprintf_s(data(), size(), size(), msg.c_str(), arg);
	#else
	vsnprintf(data(), size(), msg.c_str(), arg);
	#endif
	resize(strlen(c_str()));
	return *this;
}

tsStringBase &tsStringBase::ToUpper()
{
	tsStringBase::size_type count = size();
	tsStringBase::size_type i;
    pointer ptr = rawData();

	for (i = 0; i < count; i++)
	{
		if (ptr[i] >= 'a' && ptr[i] <= 'z')
			ptr[i] -= 0x20;
	}
	return *this;
}

tsStringBase &tsStringBase::ToLower()
{
	tsStringBase::size_type count = size();
	tsStringBase::size_type i;
    pointer ptr = rawData();

	for (i = 0; i < count; i++)
	{
		if (ptr[i] >= 'A' && ptr[i] <= 'Z')
			ptr[i] += 0x20;
	}
	return *this;
}

tsStringBase tsStringBase::substring(tsStringBase::size_type start, tsStringBase::size_type length) const
{
	if (start >= size() || length == 0)
		return "";
	if (start + length >= size())
	{
		return tsStringBase(&c_str()[start]);
	}
	return tsStringBase(&c_str()[start], length);
}
tsStringBase tsStringBase::substr(tsStringBase::size_type start, tsStringBase::size_type length) const
{
	return substring(start, length);
}

tsStringBase tsStringBase::right(tsStringBase::size_type length) const
{
	tsStringBase tmp = *this;

	if (tmp.size() > length)
		tmp.DeleteAt(0, tmp.size() - length);
	return tmp;
}

tsStringBase tsStringBase::left(tsStringBase::size_type length) const
{
	tsStringBase tmp = *this;

	if (tmp.size() > length)
		tmp.resize(length);
	return tmp;
}

tsStringBase &tsStringBase::Trim()
{
	return Trim(("\t\r\n "));
}

tsStringBase &tsStringBase::Trim(const_pointer trimmers)
{
	TrimStart(trimmers);
	return TrimEnd(trimmers);
}

tsStringBase &tsStringBase::TrimStart()
{
	return TrimStart(("\t\r\n "));
}

tsStringBase &tsStringBase::TrimStart(const_pointer trimmers)
{
	difference_type index = find_first_not_of(trimmers);

	DeleteAt(0, index);
	return *this;
}

tsStringBase &tsStringBase::TrimEnd()
{
	return TrimEnd(("\t\r\n "));
}

tsStringBase &tsStringBase::TrimEnd(const_pointer trimmers)
{
	difference_type index = find_last_not_of(trimmers);

	if (index < (difference_type)(size()) - 1)
		resize(index + 1);
	return *this;
}

std::ostream & operator << (std::ostream &Output, const tsStringBase &obj)
{
	Output << tsStringBase(obj).c_str();
	return Output;
}
std::wostream & operator << (std::wostream &Output, const tsStringBase &obj)
{
	Output << obj.c_str();
	return Output;
}

tsStringBase tsStringBase::PadLeft(tsStringBase::size_type width, value_type padding) const
{
	tsStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsStringBase(padding, width - tmp.size()));
	}
	return tmp;
}

tsStringBase tsStringBase::PadRight(tsStringBase::size_type width, value_type padding) const
{
	tsStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	return tmp;
}

tsStringBase tsStringBase::TruncOrPadLeft(tsStringBase::size_type width, value_type padding) const
{
	tsStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsStringBase(padding, width - tmp.size()));
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsStringBase tsStringBase::TruncOrPadRight(tsStringBase::size_type width, value_type padding) const
{
	tsStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsStringBase tsStringBase::ToUTF8() const
{
	return *this;
}

bool operator==(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool operator!=(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool operator<(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool operator<=(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool operator>(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool operator>=(const tsStringBase& lhs, const tsStringBase& rhs)
{
	return lhs.compare(rhs) >= 0;
}


void swap(tsStringBase &lhs, tsStringBase &rhs)
{
	lhs.swap(rhs);
}

tsStringBase& operator<<(tsStringBase& string, char val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, int8_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, int16_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, int32_t val)
{
	return string.append(val);
}
#ifdef _MSC_VER
tsStringBase& operator<<(tsStringBase& string, long val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, unsigned long val)
{
	return string.append(val);
}
#endif
tsStringBase& operator<<(tsStringBase& string, int64_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, uint8_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, uint16_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, uint32_t val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, uint64_t val)
{
	return string.append(val);
}
//tsStringBase& operator<<(tsStringBase& string, const char* val)
//{
//	return string.append(val);
//}
tsStringBase& operator<<(tsStringBase& string, const tsStringBase& val)
{
	return string.append(val);
}
tsStringBase& operator<<(tsStringBase& string, enum SpecialStrings val)
{
	switch (val)
	{
	case lf:
	case SpecialStrings::endl:
		string.append('\n');
		break;
	case tab:
		string.append('\t');
		break;
	case nullchar:
		string.resize(string.size() + 1, 0);
		break;
	case cr:
		string.append('\r');
		break;
	case crlf:
		string.append("\r\n");
		break;
	}
	return string;
}