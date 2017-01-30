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
#include "ConvertUTF.h"

#define MemAllocSize 100

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif // MIN

const CryptoUtf16::size_type CryptoUtf16::npos = (size_type)(-1);

CryptoUtf16::CryptoUtf16() : m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
}
CryptoUtf16::CryptoUtf16(size_type count, value_type ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(count, ch);
}
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj, size_type pos) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		resize(obj.size() - pos);
		obj.copy(m_data, size(), pos);
	}
}
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj, size_type pos, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		if (count + pos > obj.size())
			count = obj.size() - pos;

		resize(count);
		obj.copy(m_data, count, pos);
	}
}
CryptoUtf16::CryptoUtf16(const_pointer data, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr || count == 0)
		reserve(0);
	else
	{
		resize(count);
		memcpy(m_data, data, count * sizeof(value_type));
	}
}
CryptoUtf16::CryptoUtf16(const_pointer data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		size_type Len = UTF16Length((const UTF16*)data);
		if (Len == 0)
			reserve(0);
		else
		{
			resize(Len);
			memcpy(m_data, data, Len * sizeof(value_type));
		}
	}
}
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (obj.size() == 0)
		reserve(0);
	else
	{
		resize(obj.size());
		obj.copy(m_data, size(), 0);
	}
}
CryptoUtf16::CryptoUtf16(CryptoUtf16 &&obj)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
CryptoUtf16::CryptoUtf16(std::initializer_list<value_type> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
CryptoUtf16::CryptoUtf16(const char *data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		append(data);
	}
}
CryptoUtf16::CryptoUtf16(const tsStringBase& data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(data.data(), data.size());
}
CryptoUtf16::CryptoUtf16(size_type count, char ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(count, ch);
}
CryptoUtf16::CryptoUtf16(const char *data, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(data, count);
}
CryptoUtf16::CryptoUtf16(std::initializer_list<char> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	tsStringBase tmp(init);
	append(tmp);
}
CryptoUtf16::~CryptoUtf16()
{
	if (m_data != nullptr)
	{
		if (m_used > 0)
			memset(m_data, 0, m_used * sizeof(value_type));
		cryptoDelete(m_data);
		m_data = nullptr;
	}
	m_used = 0;
	m_allocated = -1;
}
CryptoUtf16 &CryptoUtf16::operator=(const CryptoUtf16 &obj)
{
	copyFrom(obj);
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(CryptoUtf16 &&obj)
{
	if (&obj != this)
	{
		resize(0);
		if (m_data != nullptr)
			cryptoDelete(m_data);

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
CryptoUtf16 &CryptoUtf16::operator=(const_pointer data) /* zero terminated */
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = UTF16Length((const UTF16*)data);

		resize(len);
		memcpy(m_data, data, len * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(value_type obj)
{
	resize(1);
	m_data[0] = obj;
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(std::initializer_list<value_type> iList)
{
	clear();
	append(iList);
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(const tsStringBase& setTo)
{
	clear();
	return append(setTo);
}
CryptoUtf16 &CryptoUtf16::operator=(const char* setTo)
{
	clear();
	return append(setTo);
}
CryptoUtf16& CryptoUtf16::assign(size_type count, value_type ch)
{
	clear();
	return append(count, ch);
}
CryptoUtf16& CryptoUtf16::assign(const CryptoUtf16 &obj)
{
	if (this != &obj)
	{
		clear();
		return append(obj);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(const CryptoUtf16 &obj, size_type pos, size_type count)
{
	return assign(obj.substr(pos, count));
}
CryptoUtf16& CryptoUtf16::assign(CryptoUtf16 &&obj)
{
	if (this != &obj)
	{
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
CryptoUtf16& CryptoUtf16::assign(const_pointer newData, size_type count)
{
	if (newData == nullptr || count == 0)
		resize(0);
	else
	{
		resize(count);
		memcpy(m_data, newData, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(const_pointer newData)
{
	if (newData == nullptr)
		resize(0);
	else
	{
		size_type count = UTF16Length((const UTF16*)newData);
		resize(count);
		memcpy(m_data, newData, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(std::initializer_list<value_type> iList)
{
	clear();
	append(iList);
	return *this;
}
CryptoUtf16::reference CryptoUtf16::at(size_type index)
{
	if (index >= m_used)
		throw std::out_of_range("index");
	return m_data[index];
}
CryptoUtf16::const_reference CryptoUtf16::at(size_type index) const
{
	if (index >= m_used)
		throw std::out_of_range("index");
	return m_data[index];
}
CryptoUtf16::pointer CryptoUtf16::data()
{
	return m_data;
}
CryptoUtf16::const_pointer CryptoUtf16::data() const
{
	return m_data;
}
CryptoUtf16::const_pointer CryptoUtf16::c_str() const
{
	return m_data;
}
CryptoUtf16::reference CryptoUtf16::front()
{
	return m_data[0];
}
CryptoUtf16::const_reference CryptoUtf16::front() const
{
	return m_data[0];
}
CryptoUtf16::reference CryptoUtf16::back()
{
	if (empty())
		throw std::out_of_range("index");
	return m_data[m_used - 1];
}
CryptoUtf16::const_reference CryptoUtf16::back() const
{
	if (empty())
		throw std::out_of_range("index");
	return m_data[m_used - 1];
}
CryptoUtf16::reference CryptoUtf16::operator[](size_type index)
{
	return at(index);
}
CryptoUtf16::const_reference CryptoUtf16::operator[](size_type index) const
{
	return at(index);
}
bool CryptoUtf16::empty() const
{
	return m_used == 0;
}
CryptoUtf16::size_type CryptoUtf16::size() const
{
	return m_used;
}
CryptoUtf16::size_type CryptoUtf16::length() const
{
	return m_used;
}
CryptoUtf16::size_type CryptoUtf16::max_size() const
{
	return 0x7FFFFFFF;
}

_Post_satisfies_(this->m_data != 0)
void CryptoUtf16::reserve(size_type newSize)
{
	if (newSize > max_size())
		throw std::length_error("newSize");
	if ((difference_type)newSize > m_allocated)
	{
		pointer tmp;
		size_type origNewSize = newSize;

		{
			if (newSize > 20000)
				newSize += 1024;
			else
				newSize += MemAllocSize;
			tmp = (value_type*)cryptoNew(sizeof(value_type) * (newSize + 1));
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
				cryptoDelete(m_data);
			}

			m_data = tmp;
			m_allocated = newSize;
		}
	}
}
CryptoUtf16::size_type CryptoUtf16::capacity() const
{
	return m_allocated;
}
void CryptoUtf16::clear()
{
	resize(0);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, size_type count, value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	for (size_type i = 0; i < count; i++)
	{
		m_data[index + i] = ch;
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const_pointer s)
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type oldsize = size();
	size_type count = UTF16Length((const UTF16*)s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const_pointer s, size_type count)
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const CryptoUtf16& str)
{
	size_type oldsize = size();
	size_type count = str.size();

	if (count == 0)
		return *this;
	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], str.data(), count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const CryptoUtf16& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
CryptoUtf16& CryptoUtf16::erase(size_type pos, size_type count)
{
	if (pos > size())
		throw std::out_of_range("index");
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - pos));
		resize(size() - count);
	}
	return *this;
}
void CryptoUtf16::push_back(ts_wchar ch)
{
	resize(size() + 1, ch);
}
void CryptoUtf16::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}
CryptoUtf16 &CryptoUtf16::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const CryptoUtf16 &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const CryptoUtf16 &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
CryptoUtf16 &CryptoUtf16::append(const_pointer data, size_type count)
{
	if (count > 0)
	{
		size_type oldUsed = m_used;
		resize(oldUsed + count);
		memcpy(&m_data[oldUsed], data, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const_pointer data)
{
	if (data == nullptr)
		return *this;
	return append(data, UTF16Length((const UTF16*)data));
}
CryptoUtf16 &CryptoUtf16::append(std::initializer_list<value_type> list)
{
	size_type index = size();
	resize(size() + list.size());

	for (auto i = list.begin(); i != list.end(); ++i)
	{
		m_data[index++] = *i;
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator += (const CryptoUtf16& str)
{
	return append(str);
}
CryptoUtf16 &CryptoUtf16::operator += (value_type ch)
{
	return append(ch);
}
CryptoUtf16 &CryptoUtf16::operator += (const_pointer s)
{
	return append(s);
}
CryptoUtf16 &CryptoUtf16::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}
int CryptoUtf16::compare(const CryptoUtf16& str) const
{
	size_type count = MIN(size(), str.size());
	int diff = 0;

	diff = memcmp(m_data, str.m_data, count * sizeof(value_type));
	if (diff != 0)
		return diff;
	if (size() > str.size())
		return 1;
	if (size() < str.size())
		return -1;
	return 0;
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const CryptoUtf16& str) const
{
	return substr(pos1, count1).compare(str);
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const CryptoUtf16& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int CryptoUtf16::compare(const_pointer s) const
{
	size_type len = UTF16Length((const UTF16*)s);
	size_type count = MIN(size(), len);
	int diff = 0;

	diff = memcmp(m_data, s, count * sizeof(value_type));
	if (diff != 0)
		return diff;
	if (size() > len)
		return 1;
	if (size() < len)
		return -1;
	return 0;
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const CryptoUtf16& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const CryptoUtf16& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
CryptoUtf16 CryptoUtf16::substr(size_type index, size_type count) const
{
	if (index >= size() || count == 0)
		return CryptoUtf16();
	if (index + count >= size())
	{
		count = size() - index;
	}
	return CryptoUtf16(&c_str()[index], count);
}
CryptoUtf16::size_type CryptoUtf16::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw std::out_of_range("index");
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
_Post_satisfies_(this->m_data != nullptr)
void CryptoUtf16::resize(size_type newSize)
{
	resize(newSize, 0);
}
_Post_satisfies_(this->m_data != nullptr)
void CryptoUtf16::resize(size_type newSize, ts_wchar value)
{
	reserve(newSize);
	if (capacity() < newSize)
		throw std::bad_alloc();

	if (newSize > m_used)
	{
		for (size_type i = 0; i < newSize - m_used; i++)
			m_data[m_used + i] = value;
		m_used = newSize;
	}
	else if (newSize < m_used)
	{
		memset(&m_data[newSize], 0, (m_used - newSize) * sizeof(value_type));
		m_used = newSize;
	}
}
void CryptoUtf16::swap(CryptoUtf16 &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
}
CryptoUtf16::size_type CryptoUtf16::find(const CryptoUtf16& str, size_type pos) const
{
	size_type i;
	size_type len = 0;

	len = str.size();
	if (len == 0)
		return npos;

	if (pos + len > m_used)
		return npos;
	for (i = pos; i < m_used - len + 1; i++)
	{
		const_pointer in_data_c_str = str.c_str();
		if (memcmp(in_data_c_str, &m_data[i], len * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type i;

	if (count == 0)
		return npos;

	if (pos + count > m_used)
		return npos;
	for (i = pos; i < m_used - count + 1; i++)
	{
		if (memcmp(s, &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	return find(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find(value_type ch, size_type pos) const
{
	size_type i;

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
CryptoUtf16::size_type CryptoUtf16::rfind(const CryptoUtf16& str, size_type pos) const
{
	size_type count = str.size();

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(str.c_str(), &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::rfind(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(s, &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	return rfind(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::rfind(value_type ch, size_type pos) const
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
CryptoUtf16::size_type CryptoUtf16::find_first_of(const CryptoUtf16& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
CryptoUtf16::const_pointer CryptoUtf16::WcsChr(const_pointer list, value_type ch, size_type count)
{
	if (list == nullptr || count == 0)
		return nullptr;
	for (size_type i = 0; i < count; i++)
	{
		if (list[i] == ch)
			return &list[i];
	}
	return nullptr;
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (WcsChr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const CryptoUtf16& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (WcsChr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(value_type ch, size_type pos) const
{
	size_type i;

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
CryptoUtf16::size_type CryptoUtf16::find_last_of(const CryptoUtf16& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (WcsChr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const CryptoUtf16& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (WcsChr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, UTF16Length((const UTF16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(value_type ch, size_type pos) const
{
	difference_type i;

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
// TecSec Extensions
tsStringBase CryptoUtf16::toUtf8() const
{
	tsStringBase tmp;

	tmp.resize(UTF16toUTF8Length((const UTF16*)m_data, (const UTF16*)(m_data + m_used), false, lenientConversion));
	const UTF16* srcStart = (const UTF16*)m_data;
	UTF8 *destStart = (UTF8*)tmp.data();
	if (ConvertUTF16toUTF8(&srcStart, (const UTF16*)(m_data + m_used), &destStart, (UTF8*)(tmp.data() + m_used), false, lenientConversion) != conversionOK)
		tmp.resize(0);
	return tmp;
}
CryptoUtf16& CryptoUtf16::assign(const char *newData, size_type count)
{
	clear();
	return append(newData, count);
}
CryptoUtf16& CryptoUtf16::assign(const char *newData)
{
	clear();
	return append(newData);
}
CryptoUtf16& CryptoUtf16::assign(const tsStringBase &obj)
{
	clear();
	return append(obj);
}
CryptoUtf16& CryptoUtf16::assign(std::initializer_list<char> iList)
{
	clear();
	return append(iList);
}
CryptoUtf16& CryptoUtf16::assign(value_type data)
{
	clear();
	return append(data);
}
CryptoUtf16& CryptoUtf16::assign(char data)
{
	clear();
	return append(data);
}
CryptoUtf16& CryptoUtf16::assign(int16_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(int32_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(int64_t val)
{
	clear();
	return append(val);
}
// CryptoUtf16& CryptoUtf16::assign(uint16_t val)
// {
// 	clear();
// 	return append(val);
// }
CryptoUtf16& CryptoUtf16::assign(uint32_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(uint64_t val)
{
	clear();
	return append(val);
}
CryptoUtf16::value_type CryptoUtf16::c_at(size_type index) const
{
	return at(index);
}
CryptoUtf16::pointer CryptoUtf16::rawData()
{
	return data();
}
CryptoUtf16& CryptoUtf16::insert(size_type index, size_type count, char ch)
{
	return insert(index, count, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, char ch)
{
	return insert(index, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const char* s)
{
	return insert(index, CryptoUtf16(s));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const char* s, size_type count)
{
	return insert(index, CryptoUtf16(s, count));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const tsStringBase& str)
{
	return insert(index, CryptoUtf16(str));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const tsStringBase& str, size_type index_str, size_type count)
{
	return insert(index, CryptoUtf16(str.substr(index_str, count)));
}
CryptoUtf16 &CryptoUtf16::operator=(std::initializer_list<char> iList)
{
	return append(iList);
}
void CryptoUtf16::push_back(char ch)
{
	resize(size() + 1, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::append(size_type len, char ch)
{
	resize(size() + len, (value_type)ch);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(const tsStringBase &obj)
{
	return append(obj.data(), obj.size());
}
CryptoUtf16& CryptoUtf16::append(const tsStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
CryptoUtf16& CryptoUtf16::append(const char* s, size_type count)
{
	if (s == nullptr)
	{
		return *this;
	}
	size_type oldSize = size();

	resize(oldSize + UTF8toUTF16Length((UTF8*)s, (UTF8*)(s + count), lenientConversion));
	const UTF8* srcStart = (UTF8*)s;
	UTF16 *destStart = (UTF16*)m_data + oldSize;
	if (ConvertUTF8toUTF16(&srcStart, (UTF8*)(s + count), &destStart, (UTF16*)(m_data + m_used), lenientConversion) != conversionOK)
		resize(0);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(const char* s)
{
	if (s == nullptr)
	{
		return *this;
	}
	size_type oldSize = size();

	size_type Len = strlen(s);
	resize(oldSize + UTF8toUTF16Length((UTF8*)s, (UTF8*)(s + Len), lenientConversion));
	const UTF8* srcStart = (UTF8*)s;
	UTF16 *destStart = (UTF16*)m_data + oldSize;
	if (ConvertUTF8toUTF16(&srcStart, (UTF8*)(s + Len), &destStart, (UTF16*)(m_data + m_used), lenientConversion) != conversionOK)
		resize(0);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(std::initializer_list<char> list)
{
	return append(tsStringBase(list));
}
CryptoUtf16& CryptoUtf16::append(value_type data)
{
	resize(size() + 1, data);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(char data)
{
	resize(size() + 1, (value_type)data);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(int16_t val)
{
	return append(tsStringBase().append(val));
}
CryptoUtf16& CryptoUtf16::append(int32_t val)
{
	return append(tsStringBase().append(val));
}
CryptoUtf16& CryptoUtf16::append(int64_t val)
{
	return append(tsStringBase().append(val));
}
// CryptoUtf16& CryptoUtf16::append(uint16_t val)
// {
// 	return append(tsStringBase().append(val));
//}
CryptoUtf16& CryptoUtf16::append(uint32_t val)
{
	return append(tsStringBase().append(val));
}
CryptoUtf16& CryptoUtf16::append(uint64_t val)
{
	return append(tsStringBase().append(val));
}
CryptoUtf16& CryptoUtf16::operator += (const tsStringBase &obj)
{
	return append(obj);
}
CryptoUtf16& CryptoUtf16::operator += (char data)
{
	return append(data);
}
CryptoUtf16& CryptoUtf16::operator += (const char* data)
{
	return append(data);
}
CryptoUtf16& CryptoUtf16::operator += (std::initializer_list<char> init)
{
	return append(init);
}
CryptoUtf16& CryptoUtf16::operator += (int16_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (int32_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (int64_t val)
{
	return append(val);
}
// CryptoUtf16& CryptoUtf16::operator += (uint16_t val)
// {
// 	return append(val);
// }
CryptoUtf16& CryptoUtf16::operator += (uint32_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (uint64_t val)
{
	return append(val);
}
int CryptoUtf16::compare(const tsStringBase& str) const
{
	return compare(CryptoUtf16(str));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const tsStringBase& str) const
{
	return compare(pos1, count1, CryptoUtf16(str));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const tsStringBase& str, size_type pos2, size_type count2) const
{
	return compare(pos1, count1, CryptoUtf16(str.substr(pos2, count2)));
}
int CryptoUtf16::compare(const char* s) const
{
	return compare(CryptoUtf16(s));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const char* s) const
{
	return compare(pos1, count1, CryptoUtf16(s));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const char* s, size_type count2) const
{
	return compare(pos1, count1, CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const tsStringBase& str)
{
	return replace(pos, count, CryptoUtf16(str));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const tsStringBase& str, size_type pos2, size_type count2)
{
	return replace(pos, count, CryptoUtf16(str.substr(pos2, count2)));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const char* s, size_type count2)
{
	return replace(pos, count, CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const char* s)
{
	return replace(pos, count, CryptoUtf16(s));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, size_type count2, char ch)
{
	return replace(pos, count, CryptoUtf16(count2, ch));
}
CryptoUtf16 CryptoUtf16::right(size_type length) const
{
	if (length > size())
		return *this;
	return substr(size() - length);
}
CryptoUtf16 CryptoUtf16::left(size_type length) const
{
	return substr(0, length);
}
CryptoUtf16& CryptoUtf16::padLeft(size_type length, value_type value)
{
	size_type oldLen = size();

	if (oldLen < length)
	{
		CryptoUtf16 tmp(length - oldLen, value);
		insert(0, tmp);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::padRight(size_type length, value_type value)
{
	if (size() < length)
	{
		resize(length, value);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::truncOrPadLeft(size_type length, value_type value)
{
	if (size() > length)
	{
		resize(length);
	}
	else
	{
		return padLeft(length, value);
	}
	return *this;
}
void CryptoUtf16::copyFrom(const CryptoUtf16 &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used * sizeof(value_type));
}

void swap(CryptoUtf16 &lhs, CryptoUtf16 &rhs)
{
	lhs.swap(rhs);
}
bool operator==(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool operator!=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool operator<(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool operator<=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool operator>(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool operator>=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) >= 0;
}


std::ostream& operator << (std::ostream &Output, const CryptoUtf16 &obj)
{
	Output << obj.toUtf8();
	return Output;
}
std::wostream& operator << (std::wostream &Output, const CryptoUtf16 &obj)
{
	Output << obj.data();
	return Output;
}
CryptoUtf16& operator<<(CryptoUtf16& string, char val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, int8_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, int16_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, int32_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, int64_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, uint8_t val)
{
	return string.append(val);
}
// CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, uint16_t val)
// {
// 	return string.append(val);
// }
CryptoUtf16& operator<<(CryptoUtf16& string, uint32_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, uint64_t val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, const char* val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, const tsStringBase& val)
{
	return string.append(val);
}
CryptoUtf16& operator<<(CryptoUtf16& string, const CryptoUtf16& val)
{
	return string.append(val);
}

