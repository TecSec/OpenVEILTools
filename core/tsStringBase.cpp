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
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	reserve(0);
};
tsStringBase::tsStringBase(std::initializer_list<value_type> init) :
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	tsStringBase::size_type index = 0;
	reserve(0);
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsStringBase::tsStringBase(tsStringBase &&obj) :
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
tsStringBase::tsStringBase(const_pointer data, tsStringBase::size_type Len) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(m_data, data, Len * sizeof(data[0]));
	}
	else
		reserve(0);
};
tsStringBase::tsStringBase(const tsStringBase &obj) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
	copyFrom(obj);
};
tsStringBase::tsStringBase(const_pointer data) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	tsStringBase::size_type Len = 0;
	if (data != nullptr)
	{
		Len = strlen(data);
	}
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(m_data, data, Len * sizeof(value_type));
	}
	else
		reserve(0);
}
tsStringBase::tsStringBase(value_type data, tsStringBase::size_type numChars) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
	resize(numChars, data);
}
tsStringBase::~tsStringBase()
{
	if (m_data != nullptr)
	{
		if (m_used > 0)
			memset(m_data, 0, m_used * sizeof(value_type));
		delete[] m_data;
		m_data = nullptr;
	}
	m_used = 0;
	m_allocated = -1;
};
//tsStringBase::operator LPCTSTR ()
//{
//	return c_str();
//}
tsStringBase &tsStringBase::operator= (tsStringBase &&obj)
{
	if (&obj != this)
	{
		resize(0);
		if (m_data != nullptr)
			delete[] m_data;

		m_data = obj.m_data;
		m_used = obj.m_used;
		m_allocated = obj.m_allocated;

		obj.m_data = nullptr;
		obj.m_used = 0;
		obj.m_allocated = -1;
		obj.reserve(0);
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
	m_data[0] = data;
	return *this;
}
tsStringBase &tsStringBase::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsStringBase &tsStringBase::operator+= (const tsStringBase &obj)
{
	tsStringBase::size_type len = 0;
	tsStringBase::size_type oldUsed = m_used;
	if (obj.size() > 0)
	{
		len = obj.size();
		resize(m_used + len);
		memcpy(&m_data[oldUsed], obj.m_data, len * sizeof(value_type));
	}
	return *this;
}
tsStringBase &tsStringBase::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsStringBase(data);
}
tsStringBase &tsStringBase::operator+= (value_type data)
{
	tsStringBase::size_type len = 0;
	tsStringBase::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
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

	diff = memcmp(m_data, str.m_data, count);
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

	diff = memcmp(m_data, s, count);
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
	return m_used;
}
tsStringBase::size_type tsStringBase::length() const
{
	return m_used;
}
void tsStringBase::clear()
{
	resize(0);
}
_Post_satisfies_(this->m_data != nullptr) void tsStringBase::reserve(tsStringBase::size_type newSize)
{
	if (newSize > max_size())
		throw std::length_error("String too long");
	if ((ptrdiff_t)newSize > m_allocated)
	{
		pointer tmp;
		size_type origNewSize = newSize;

		{
			if (newSize > 20000)
				newSize += 1024;
			else
				newSize += MemAllocSize;
			tmp = new value_type[newSize + 1];
			if (tmp == nullptr)
			{
				throw std::bad_alloc();
			}
			memset(&tmp[m_used], 0, (origNewSize - m_used) * sizeof(value_type));
			memset(&tmp[origNewSize], 0, (newSize + 1 - origNewSize) * sizeof(value_type));
			if (m_data != nullptr)
			{
				memcpy(tmp, m_data, m_used * sizeof(value_type));
				memset(m_data, 0, m_used * sizeof(value_type));
				delete[] m_data;
			}

			m_data = tmp;
			m_allocated = newSize;
		}
	}
}
tsStringBase::size_type tsStringBase::capacity() const
{
	return m_allocated;
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
	reserve(newSize);
	if (capacity() < newSize)
		throw std::bad_alloc();

	if (newSize > m_used)
	{
		memset(&m_data[m_used], value, newSize - m_used);
		m_used = newSize;
	}
	else if (newSize < m_used)
	{
		memset(&m_data[newSize], 0, m_used - newSize);
		m_used = newSize;
	}
}
tsStringBase::reference tsStringBase::at(tsStringBase::size_type index)
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
tsStringBase::const_reference tsStringBase::at(tsStringBase::size_type index) const
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
tsStringBase::value_type tsStringBase::c_at(tsStringBase::size_type index) const
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
//
// used to access the buffer directly.
// In all cases this will return a buffer for this class instance only.
//
// NOTE:  Do not access data beyond size() characters
//
tsStringBase::pointer tsStringBase::data()
{
	return m_data;
}
tsStringBase::const_pointer tsStringBase::data() const
{
	return m_data;
}
tsStringBase::reference tsStringBase::front()
{
	return m_data[0];
}
tsStringBase::const_reference tsStringBase::front() const
{
	return m_data[0];
}
tsStringBase::reference tsStringBase::back()
{
	if (empty())
		throw std::out_of_range("index");
	return m_data[m_used - 1];
}
tsStringBase::const_reference tsStringBase::back() const
{
	if (empty())
		throw std::out_of_range("index");
	return m_data[m_used - 1];
}
bool tsStringBase::empty() const
{
	return m_used == 0;
}
tsStringBase::const_pointer tsStringBase::c_str() const
{
	return m_data;
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
		memcpy(m_data, newData, size * sizeof(value_type));
	}
	return *this;
}
tsStringBase &tsStringBase::assign(std::initializer_list<value_type> iList)
{
	size_type pos = size();

	resize(iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsStringBase::size_type tsStringBase::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw std::out_of_range("index");
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
void tsStringBase::copyFrom(const tsStringBase &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used * sizeof(value_type));
}
void tsStringBase::swap(tsStringBase &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
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
	if (data == 0)
	{
		return *this;
	}
	tsStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	memmove(&m_data[1], m_data, oldUsed * sizeof(value_type));
	m_data[0] = data;
	return *this;
}
tsStringBase &tsStringBase::prepend(uint8_t data)
{
	tsStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	memmove(&m_data[1], m_data, oldUsed * sizeof(value_type));
	m_data[0] = data;
	return *this;
}
tsStringBase &tsStringBase::prepend(const tsStringBase &obj)
{
	if (obj.size() > 0)
	{
		tsStringBase::size_type oldUsed = m_used;
		resize(oldUsed + obj.size());
		memmove(&m_data[obj.size()], m_data, oldUsed * sizeof(value_type));
		memcpy(m_data, obj.c_str(), obj.size() * sizeof(value_type));
	}
	return *this;
}
tsStringBase &tsStringBase::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
tsStringBase &tsStringBase::append(const tsStringBase &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		tsStringBase::size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
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

	resize(size() + list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsStringBase &tsStringBase::append(value_type data)
{
	tsStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	m_data[oldUsed] = data;
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
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - pos - count));
		resize(size() - count);
	}
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::size_type count, tsStringBase::value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::const_pointer s)
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	size_type oldsize = size();
	size_type count = strlen(s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, tsStringBase::const_pointer s, tsStringBase::size_type count)
{
	if (s == nullptr)
		throw std::invalid_argument("s is NULL");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, const tsStringBase& str)
{
	size_type oldsize = size();
	size_type count = str.size();

	if (count == 0)
		return *this;
	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], str.data(), count);
	return *this;
}
tsStringBase& tsStringBase::insert(tsStringBase::size_type index, const tsStringBase& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsStringBase& tsStringBase::insert(size_type pos, std::initializer_list<value_type> iList)
{
	size_type oldsize = size();

	if (pos >= size())
	{
		append(iList);
		return *this;
	}
	resize(size() + iList.size());
	memmove(&m_data[pos + iList.size()], &m_data[pos], sizeof(value_type) * (oldsize - pos));
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
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
	tsStringBase::size_type oldLen = m_used;

	if (value.size() == 0)
		return *this;
	if (offset > m_used)
	{
		offset = m_used;
	}
	resize(oldLen + value.size());
	memmove(&m_data[offset + value.size()], &m_data[offset], (oldLen - offset) * sizeof(value_type));
	memcpy(&m_data[offset], value.c_str(), value.size() * sizeof(value_type));
	return *this;
}

tsStringBase &tsStringBase::DeleteAt(tsStringBase::size_type offset, tsStringBase::size_type count)
{
	if (count == 0)
		return *this;

	if (offset >= m_used)
		return *this;

	if (count + offset > m_used)
		count = m_used - offset;

	if (count + offset < m_used)
	{
		memmove(&m_data[offset], &m_data[offset + count], (m_used - offset - count) * sizeof(value_type));
	}
	resize(size() - count);
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
#ifdef HAVE_ISBADREADPTR
	if (IsBadReadPtr(i_newData, repLen))
		return *this;
#endif
	if (i_Begin >= m_used)
		return *this;
	if (i_End >= m_used)
		i_End = m_used - 1;

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
	if (findLen < 1 || findLen > m_used)
		return *this;
	if (count == -1)
		count = (int32_t)max_size();
	posi = 0;
	while (posi + findLen <= m_used && count > 0)
	{
		if (strncmp(&m_data[posi], find.c_str(), findLen) == 0)
		{
			count--;
			if (findLen == repLen)
			{
				memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else if (findLen < repLen)
			{
				tsStringBase::size_type oldLen = size();

				resize(oldLen + repLen - findLen);
				if (oldLen - findLen > posi)
					memmove(&m_data[posi + repLen], &m_data[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else
			{
				tsStringBase::size_type oldLen = size();

				if (oldLen - findLen > posi)
				{
					memmove(&m_data[posi + repLen], &m_data[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				}
				if (repLen > 0)
					memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
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

	len = str.size();
	if (len == 0)
		return npos;

	if (pos + len > m_used)
		return npos;
	for (i = pos; i < m_used - len + 1; i++)
	{
		const_pointer in_data_c_str = str.c_str();
		if (memcmp(in_data_c_str, &m_data[i], len) == 0)
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

	if (count == 0)
		return npos;

	if (pos + count > m_used)
		return npos;
	for (i = pos; i < m_used - count + 1; i++)
	{
		if (memcmp(s, &m_data[i], count) == 0)
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

	len = strlen(s);
	if (len == 0)
		return npos;
	if (pos + len > m_used)
		return npos;
	for (i = pos; i < m_used - len + 1; i++)
	{
		if (memcmp(s, &m_data[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsStringBase::size_type tsStringBase::find(value_type ch, size_type pos) const
{
	tsStringBase::size_type i;

	if (pos >= m_used)
		return npos;
	for (i = pos; i < m_used; i++)
	{
		if (m_data[i] == ch)
		{
			return i;
		}
	}
	return npos;
}

tsStringBase::size_type tsStringBase::rfind(const tsStringBase& str, size_type pos) const
{
	size_type count = str.size();

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(str.c_str(), &m_data[i], count) == 0)
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

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(s, &m_data[i], count) == 0)
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

	for (i = pos; i >= 0; i--)
	{
		if (m_data[i] == ch)
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

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (memchr(s, m_data[i], count) != nullptr)
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

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (memchr(s, m_data[i], count) == nullptr)
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

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (m_data[i] != ch)
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

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) != nullptr)
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

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) == nullptr)
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

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (m_data[i] != ch)
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

	for (i = 0; i < count; i++)
	{
		if (m_data[i] >= 'a' && m_data[i] <= 'z')
			m_data[i] -= 0x20;
	}
	return *this;
}

tsStringBase &tsStringBase::ToLower()
{
	tsStringBase::size_type count = size();
	tsStringBase::size_type i;

	for (i = 0; i < count; i++)
	{
		if (m_data[i] >= 'A' && m_data[i] <= 'Z')
			m_data[i] += 0x20;
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