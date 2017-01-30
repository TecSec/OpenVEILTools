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

#define BASE64_ENCODE_RATIO 1.4
#define BASE64_DECODE_RATIO 1.3

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif// MIN

const tsData::size_type tsData::npos = (size_type)(-1);

tsData::tsData() : m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
}
tsData::tsData(size_type count, value_type value) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(count, value);
}
tsData::tsData(const tsData &obj, size_type pos) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		resize(obj.size() - pos);
		obj.copy(m_data, size(), pos);
	}
}
tsData::tsData(const tsData &obj, size_type pos, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
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
tsData::tsData(const_pointer data, size_type Len) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr || Len == 0)
		reserve(0);
	else
	{
		resize(Len);
		memcpy(m_data, data, Len);
	}
}
tsData::tsData(const_pointer data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		size_type Len = (size_type)strlen((const char*)data);
		if (Len == 0)
			reserve(0);
		else
		{
			resize(Len);
			memcpy(m_data, data, Len);
		}
	}
}
tsData::tsData(const char* data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		size_type Len = (size_type)strlen(data);
		if (Len == 0)
			reserve(0);
		else
		{
			resize(Len);
			memcpy(m_data, data, Len);
		}
	}
}
tsData::tsData(const char* value, DataStringType type) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
	switch (type)
	{
	case ASCII:
		append(value);
		break;
	//case OID:
	//	return substring(offset, numberOfBytes);
	case HEX:
		FromHexString(value);
		break;
	case BASE64:
		FromBase64(value);
		break;
	case BASE64URL:
		FromBase64(value, true);
		break;
	}
}
tsData::tsData(const tsData &obj) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (obj.size() == 0)
		reserve(0);
	else
	{
		resize(obj.size());
		obj.copy(m_data, size(), 0);
	}
}
tsData::tsData(tsData &&obj)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
tsData::tsData(std::initializer_list<value_type> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize((size_type)init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsData::tsData(std::initializer_list<char> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize((size_type)init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsData::tsData(value_type ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(1, ch);
}
tsData::tsData(char ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(1, (value_type)ch);
}

tsData::~tsData()
{
	if (m_data != nullptr)
	{
		if (m_used > 0)
			memset(m_data, 0, m_used);
		delete [] m_data;
		m_data = nullptr;
	}
	m_used = 0;
	m_allocated = -1;
}

tsData &tsData::operator=(const tsData &obj)
{
	copyFrom(obj);
	return *this;
}
tsData &tsData::operator=(tsData &&obj)
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
tsData &tsData::operator=(const_pointer data) /* zero terminated */
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = (size_type)strlen((const char *)data);

		resize(len);
		memcpy(m_data, data, len);
	}
	return *this;
}
tsData &tsData::operator=(value_type obj)
{
	resize(1);
	m_data[0] = obj;
	return *this;
}
tsData &tsData::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsData &tsData::operator=(const char *data) // zero terminated - tecsec addition
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = (size_type)strlen(data);

		resize(len);
		memcpy(m_data, data, len);
	}
	return *this;
}

tsData &tsData::operator=(std::initializer_list<char> iList)
{
	assign(iList);
	return *this;
}

tsData& tsData::assign(size_type count, value_type ch)
{
	clear();
	resize(count, ch);
	return *this;
}
tsData& tsData::assign(const tsData &obj)
{
	if (this == &obj)
		return *this;
	return assign(obj.c_str(), obj.size());
}
tsData& tsData::assign(const tsData &obj, size_type pos, size_type count)
{
	if (this == &obj)
		return *this;
	return assign(obj.substr(pos, count));
}
tsData& tsData::assign(tsData &&obj)
{
	if (this == &obj)
		return *this;

	resize(0);
	if (m_data != nullptr)
		delete [] m_data;

	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);

	return *this;
}
tsData& tsData::assign(const_pointer newData, size_type count)
{
	resize(count);
	if (count > 0 && newData != nullptr)
	{
		memcpy(m_data, newData, count);
	}
	return *this;
}
tsData& tsData::assign(const_pointer newData)
{
	return assign(newData, (newData != nullptr) ? (size_type)strlen((const char *)newData) : 0);
}
tsData& tsData::assign(std::initializer_list<value_type> iList)
{
	size_type pos = size();

	resize((size_type)iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsData& tsData::assign(const char *newData, size_type count) // tecsec extension
{
	resize(count);
	if (count > 0 && newData != nullptr)
	{
		memcpy(m_data, newData, count);
	}
	return *this;
}
tsData& tsData::assign(const char *newData) // tecsec extension
{
	return assign(newData, (newData != nullptr) ? (size_type)strlen(newData) : 0);
}
tsData& tsData::assign(std::initializer_list<char> iList)
{
	size_type pos = size();

	resize((size_type)iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}

tsData::reference tsData::at(size_type index)
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
tsData::const_reference tsData::at(size_type index) const
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
tsData::value_type tsData::c_at(size_type index) const // tecsec addition
{
	if (index >= m_used)
	{
		throw std::out_of_range("index");
	}
	return m_data[index];
}
tsData::const_pointer tsData::data() const
{
	return m_data;
}
tsData::pointer tsData::data()
{
	return m_data;
}
tsData::pointer tsData::rawData() // tecsec addition
{
	return m_data;
}
tsData::const_pointer tsData::c_str() const
{
	return m_data;
}
tsData::reference tsData::front()
{
	return m_data[0];
}
tsData::const_reference tsData::front() const
{
	return m_data[0];
}
tsData::reference tsData::back()
{
	if (empty())
		throw std::out_of_range("back");
	return m_data[m_used - 1];
}
tsData::const_reference tsData::back() const
{
	if (empty())
		throw std::out_of_range("back");
	return m_data[m_used - 1];
}
tsData::reference tsData::operator [] (size_type index)
{
	return at(index);
}
tsData::const_reference tsData::operator [] (size_type index) const
{
	return at(index);
}

bool tsData::empty() const
{
	return m_used == 0;
}
tsData::size_type  tsData::size() const
{
	return m_used;
}
tsData::size_type  tsData::length() const
{
	return m_used;
}
tsData::size_type tsData::max_size() const
{
	return 0x7FFFFFFF;
}
_Post_satisfies_(this->m_data != nullptr) void tsData::reserve(size_type newSize)
{
	if (newSize > max_size())
		throw std::length_error("Invalid size");
	if ((difference_type)newSize > m_allocated)
	{
		pointer tmp;
		size_type origNewSize = newSize;

		{
			if (newSize > 20000)
				newSize += 1024;
			else
				newSize += MemAllocSize;
			tmp = (value_type*)new value_type[(sizeof(value_type) * (newSize + 1))];
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
tsData::size_type tsData::capacity() const
{
	return (size_type)m_allocated;
}
void tsData::clear()
{
	resize(0);
}

tsData& tsData::insert(size_type index, size_type count, value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsData& tsData::insert(size_type index, value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsData& tsData::insert(size_type index, const_pointer s)
{
	if (s == nullptr)
		throw std::invalid_argument("");

	size_type oldsize = size();
	size_type count = (size_type)strlen((const char *)s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsData& tsData::insert(size_type index, const_pointer s, size_type count)
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsData& tsData::insert(size_type index, const tsData& str)
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
tsData& tsData::insert(size_type index, const tsData& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}

tsData& tsData::erase(size_type pos, size_type count)
{
	if (pos > size())
		throw std::out_of_range("pos");
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - count - pos));
		resize(size() - count);
	}
	return *this;
}
void tsData::push_back(value_type ch)
{
	resize(size() + 1, ch);
}
void tsData::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}

tsData &tsData::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
tsData &tsData::append(const tsData &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		tsData::size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
tsData &tsData::append(const tsData &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsData &tsData::append(const_pointer data, size_type count)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsData(data, count));
}
tsData &tsData::append(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsData(data));
}
tsData &tsData::append(std::initializer_list<value_type> list)
{
	size_type pos = size();

	resize(size() + (size_type)list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}

tsData &tsData::operator+= (const tsData &obj)
{
	tsData::size_type len = 0;
	tsData::size_type oldUsed = m_used;
	if (obj.size() > 0)
	{
		len = obj.size();
		resize(m_used + len);
		memcpy(&m_data[oldUsed], obj.m_data, len * sizeof(value_type));
	}
	return *this;
}
tsData &tsData::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsData(data);
}
tsData &tsData::operator+= (value_type data)
{
	tsData::size_type len = 0;
	tsData::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
	return *this;
}
tsData &tsData::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}

int tsData::compare(const tsData& str) const
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
int tsData::compare(size_type pos1, size_type count1, const tsData& str) const
{
	return substr(pos1, count1).compare(str);
}
int tsData::compare(size_type pos1, size_type count1, const tsData& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int tsData::compare(const_pointer s) const
{
	size_type len = (size_type)strlen((const char *)s);
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
int tsData::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int tsData::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(tsData(s, count2));
}
tsData& tsData::replace(size_type pos, size_type count, const tsData& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, const tsData& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsData tsData::substr(size_type start, size_type length) const
{
	if (start >= size() || length == 0)
		return tsData();
	if (start + length >= size())
	{
		length = size() - start;
	}
	return tsData(&c_str()[start], length);
}
tsData::size_type tsData::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw std::out_of_range("pos");
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
_Post_satisfies_(this->m_data != nullptr) void tsData::resize(size_type newSize)
{
	resize(newSize, 0);
}
_Post_satisfies_(this->m_data != nullptr) void tsData::resize(size_type newSize, value_type value)
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
void tsData::swap(tsData &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
}

tsData::size_type tsData::find(const tsData& str, size_type pos) const
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
		if (memcmp(in_data_c_str, &m_data[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsData::size_type tsData::find(const_pointer s, size_type pos, size_type count) const
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
		if (memcmp(s, &m_data[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsData::size_type tsData::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type i;
	size_type len;

	len = (size_type)strlen((const char*)s);
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
tsData::size_type tsData::find(value_type ch, size_type pos) const
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

tsData::size_type tsData::rfind(const tsData& str, size_type pos) const
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
			return (size_type)i;
		}
	}
	return npos;
}
tsData::size_type tsData::rfind(const_pointer s, size_type pos, size_type count) const
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
		if (memcmp(s, &m_data[i], count) == 0)
		{
			return (size_type)i;
		}
	}
	return npos;
}
tsData::size_type tsData::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type count = (size_type)strlen((const char*)s);
	if (count == 0)
		return npos;

	return rfind(s, pos, count);
}
tsData::size_type tsData::rfind(value_type ch, size_type pos) const
{
	if (pos >= size())
		pos = size() - 1;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (m_data[i] == ch)
		{
			return (size_type)i;
		}
	}
	return npos;
}

tsData::size_type tsData::find_first_of(const tsData& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
tsData::size_type tsData::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

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
tsData::size_type tsData::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, (size_type)strlen((const char*)s));
}
tsData::size_type tsData::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}

tsData::size_type tsData::find_first_not_of(const tsData& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
tsData::size_type tsData::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

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
tsData::size_type tsData::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, (size_type)strlen((const char*)s));
}
tsData::size_type tsData::find_first_not_of(value_type ch, size_type pos) const
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

tsData::size_type tsData::find_last_of(const tsData& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
tsData::size_type tsData::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) != nullptr)
		{
			return (size_type)i;
		}
	}
	return npos;
}
tsData::size_type tsData::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, (size_type)strlen((const char*)s));
}
tsData::size_type tsData::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}

tsData::size_type tsData::find_last_not_of(const tsData& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
tsData::size_type tsData::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) == nullptr)
		{
			return (size_type)i;
		}
	}
	return npos;
}
tsData::size_type tsData::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, (size_type)strlen((const char*)s));
}
tsData::size_type tsData::find_last_not_of(value_type ch, size_type pos) const
{
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (m_data[i] != ch)
		{
			return (size_type)i;
		}
	}
	return npos;
}




// TecSec Extensions
void  tsData::FromHexString(const char* inVal)
{
	tsStringBase inValue(inVal);

	tsStringBaseList list = inValue.split("\r\n");

	resize(384);
	clear();
	inValue.clear();
	for (difference_type i = list.size() - 1; i >= 0; i--)
	{
		list.at(i).Trim().Replace("\t", " ").Replace("0x", " ").Replace("0X", " ");
		if (list.at(i).size() == 0)
		{
			auto it = list.begin();
			std::advance(it, i);
			list.erase(it);
		}
	}
	for (size_type i = 0; i < list.size(); i++)
	{
		if (list.at(i).find_first_not_of("0123456789abcdefABCDEF ") != tsStringBase::npos)
			return;

		tsStringBaseList list2 = list.at(i).split(' ');
		for (size_type j = 0; j < list2.size(); j++)
		{
			list2.at(j).Trim();
			if (list2.at(j).size() & 1)
			{
				inValue += "0";
			}
			inValue += list2.at(j);
		}
	}

	size_type len = (size_type)inValue.size();;
	size_type posiCount = 0;
	size_type posi;
	value_type val = 0;

	resize((len / 2));
	resize(0);

	posiCount = (len & 1);
	for (posi = 0; posi < len; posi++)
	{
		if (posi == 0 && inValue[posi] == '0' && inValue[posi + 1] == 'x')
		{
			posi++;
		}
		else if (inValue[posi] >= '0' && inValue[posi] <= '9')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - '0'));
		}
		else if (inValue[posi] >= 'a' && inValue[posi] <= 'f')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'a' + 10));
		}
		else if (inValue[posi] >= 'A' && inValue[posi] <= 'F')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'A' + 10));
		}
		else
		{
			if (posiCount > 0)
			{
				posiCount = 2;
			}
		}
		if (posiCount == 2)
		{
			(*this) += val;
			posiCount = 0;
			val = 0;
		}
	}
	if (posiCount > 0)
	{
		(*this) += val;
	}
}
tsData tsData::FromHexString(size_type maxSize, size_type offset) const
{
	tsData tmp;

	tsStringBaseList list;

	if (offset > 0)
	{
		list = ToUtf8String().split("\r\n");
	}
	else
		list = ToUtf8String().split("\r\n");

	tsStringBase inValue;

	for (difference_type i = list.size() - 1; i >= 0; i--)
	{
		list[i].Trim().Replace("\t", " ").Replace("0x", " ").Replace("0X", " ");
		if (list[i].size() == 0)
		{
			auto it = list.begin();
			std::advance(it, i);
			list.erase(it);
		}
	}
	for (size_type i = 0; i < list.size(); i++)
	{
		if (list.at(i).find_first_not_of("0123456789abcdefABCDEF ") != tsStringBase::npos)
			return tmp;

		tsStringBaseList list2 = list.at(i).split(' ');
		for (size_type j = 0; j < (size_type)list2.size(); j++)
		{
			list2[j].Trim();
			if (list2[j].size() & 1)
			{
				inValue += "0";
			}
			inValue += list2[j];
		}
	}

	size_type len = (size_type)inValue.size();;
	size_type posiCount = 0;
	size_type posi;
	value_type val = 0;

	if (len > maxSize)
		len = maxSize;

	tmp.resize((len / 2));
	tmp.resize(0);

	posiCount = (len & 1);
	for (posi = 0; posi < len; posi++)
	{
		if (posi == 0 && inValue[posi] == '0' && inValue[posi + 1] == 'x')
		{
			posi++;
		}
		else if (inValue[posi] >= '0' && inValue[posi] <= '9')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - '0'));
		}
		else if (inValue[posi] >= 'a' && inValue[posi] <= 'f')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'a' + 10));
		}
		else if (inValue[posi] >= 'A' && inValue[posi] <= 'F')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'A' + 10));
		}
		else
		{
			if (posiCount > 0)
			{
				posiCount = 2;
			}
		}
		if (posiCount == 2)
		{
			tmp += val;
			posiCount = 0;
			val = 0;
		}
	}
	if (posiCount > 0)
	{
		tmp += val;
	}
	return tmp;
}
static const char *dtableUrl = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");        /* encode / decode table */
static const char *dtableNormal = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");        /* encode / decode table */
static bool  base64Encode(const char *dtable,
	bool padWithEquals,
	const uint8_t * const pInput,     /* in */
	uint32_t             ulInSize,   /* in */
	char *             outbuf,
	uint32_t * const     pulOutSize) /* out */
{
	uint32_t i, j, loopcount;
	BOOL done = FALSE;
	uint32_t sz;

	if (pInput == nullptr)
	{
		return false;
	}

	if (ulInSize == 0)
	{
		return false;
	}

	if (pulOutSize == nullptr)
	{
		return false;
	}

	/* determine the size of the output buffer */
	sz = (uint32_t)(ulInSize * BASE64_ENCODE_RATIO);
	sz += sz % 4;
	sz += 2 * (sz / 76);
	sz += 1; /* NULL terminator */
	sz += 10; /* make sure that we never have heap damage in case this computation is wrong. */

	if (outbuf == nullptr)
	{
		*pulOutSize = sz;
		return true;
	}
	if (*pulOutSize < sz)
	{
		*pulOutSize = sz;
		return false;
	}
	/* allocate the output buffer */
	memset(outbuf, 0, sz);

	i = 0;
	j = 0;
	loopcount = 0;
	while (!done) {
		uint8_t igroup[3];
		char ogroup[4];
		int n;

		igroup[0] = igroup[1] = igroup[2] = 0;
		for (n = 0; n < 3; n++) {
			if (i < ulInSize) {
				igroup[n] = pInput[i];
				i++;
			}
			else {
				done = TRUE;
				break;
			}
		}
		if (n > 0) {
			ogroup[0] = dtable[igroup[0] >> 2];
			ogroup[1] = dtable[((igroup[0] & 3) << 4) | (igroup[1] >> 4)];
			ogroup[2] = dtable[((igroup[1] & 0xF) << 2) | (igroup[2] >> 6)];
			ogroup[3] = dtable[igroup[2] & 0x3F];

			/* Replace characters in output stream with "=" pad
			characters if fewer than three characters were
			read from the end of the input stream. */

			if (padWithEquals)
			{
				if (n < 3) {
					ogroup[3] = '=';
					if (n < 2) {
						ogroup[2] = '=';
					}
				}
			}
			else
			{
				if (n < 3) {
					ogroup[3] = '\0';
					if (n < 2) {
						ogroup[2] = '\0';
					}
				}
			}

			/* Every 19 iterations of this loop that writes to the output buffer,
			add the CR & LF characters to end the line.  This is necessary to
			keep the lines exactly 76 characters long (19 * 4 = 76). */
			//if( ((loopcount % 19) == 0) && (loopcount != 0) )
			//{
			//    outbuf[j] = '\r';
			//    j++;
			//    outbuf[j] = '\n';
			//    j++;
			//} /* end if */
			for (n = 0; n < 4; n++, j++) {
				outbuf[j] = ogroup[n];
			}
			loopcount++;
		}
	}

	*pulOutSize = j;
	outbuf[j] = '\0';

	return true;
}
void  tsData::FromBase64(const char* pInput, bool base64Url, bool padWithEquals)
{
	int i = 0, n = 0;
	unsigned int j = 0, k = 0;
	value_type encodeTable[256];         /* encode / decode table */
	size_type sz;
	size_type ulInSize;
	value_type *outbuf;
	bool comment = false;

	clear();

	if (pInput == nullptr)
	{
		return;
	}
	ulInSize = (size_type)strlen(pInput);

	if (ulInSize == 0)
	{
		return;
	}

	sz = (size_type)(ulInSize / BASE64_DECODE_RATIO) + 1;
	sz += 5; /* make sure that we never have heap damage in case this computation is wrong. */

			 /* create the output buffer */
	resize(sz);

	outbuf = m_data;

	/*  Create the Base64 alphabet table */
	for (i = 0; i < 255; i++) {
		encodeTable[i] = 0x80;
	}
	for (i = 'A'; i <= 'Z'; i++) {
		encodeTable[i] = (value_type)(0 + (i - 'A'));
	}
	for (i = 'a'; i <= 'z'; i++) {
		encodeTable[i] = (value_type)(26 + (i - 'a'));
	}
	for (i = '0'; i <= '9'; i++) {
		encodeTable[i] = (value_type)(52 + (i - '0'));
	}
	if (base64Url)
	{
		encodeTable[(int)'-'] = 62;
		encodeTable[(int)'_'] = 63;
	}
	else
	{
		encodeTable[(int)'+'] = 62;
		encodeTable[(int)'/'] = 63;
	}
	encodeTable[(int)'='] = 0;

	j = 0;
	k = 0;
	for (;;) {
		value_type a[4], b[4], o[3];
		short padding;
		for (i = 0; i < 4; i++) {
			short c;
		SKIPCHAR:
			if (j < ulInSize) {
				c = pInput[j];
				j++;
			}
			else {
				resize(k);
				return;
			}

			if (c == 0) {
				/* End of stream */
				resize(k);
				return;
			}
			if (c == '-')
			{
				comment = true;
			}
			else if ((c == '\r' || c == '\n' || c == '\t' || c == ' '))
			{
				if (c == '\r' || c == '\n')
					comment = false;
				/*
				* Skip the whitespace characters
				*/
				goto SKIPCHAR;
			}
			else if (comment)
			{
				goto SKIPCHAR;
			}

			/*
			* check for invalid characters.  If found, abort.
			*/
			if (encodeTable[c] & 0x80) {
				resize(0);
				return;
			}
			a[i] = (value_type)c;
			b[i] = (value_type)encodeTable[c];
		}

		/* convert the 4 character group into the original 3 characters */
		o[0] = (value_type)((b[0] << 2) | (b[1] >> 4));
		o[1] = (value_type)((b[1] << 4) | (b[2] >> 2));
		o[2] = (value_type)((b[2] << 6) | b[3]);

		/* determine if there is any padding at the end of the string */
		if (padWithEquals)
		{
			padding = (short)((a[2] == '=' ? 1 : (a[3] == '=' ? 2 : 3)));
		}
		else
		{
			padding = (short)((a[2] == '\0' ? 1 : (a[3] == '\0' ? 2 : 3)));
		}
		for (n = 0; n < padding; n++, k++) {
			outbuf[k] = o[n];
		}

		/* if we are out of characters, there is nothing left to do */
		if (i < 1) {
			break;
		}
	}

	resize(0);
}
tsData  tsData::FromBase64(size_type maxSize, size_type offset, bool base64Url, bool padWithEquals) const
{
	int i = 0, n = 0;
	unsigned int j = 0, k = 0;
	value_type encodeTable[256];         /* encode / decode table */
	size_type sz;
	size_type ulInSize;
	value_type *outbuf;
	bool comment = false;
	tsData tmp;

	if (offset >= size())
		return tmp;

	const char *pInput = (const char*)&c_str()[offset];

	ulInSize = (size_type)strlen(pInput);

	if (ulInSize == 0)
	{
		return tmp;
	}

	sz = (size_type)(ulInSize / BASE64_DECODE_RATIO) + 1;
	sz += 5; /* make sure that we never have heap damage in case this computation is wrong. */

	if (sz > maxSize)
		sz = maxSize;

	/* create the output buffer */
	tmp.resize(sz);

	outbuf = tmp.rawData();

	/*  Create the Base64 alphabet table */
	for (i = 0; i < 255; i++) {
		encodeTable[i] = 0x80;
	}
	for (i = 'A'; i <= 'Z'; i++) {
		encodeTable[i] = (value_type)(0 + (i - 'A'));
	}
	for (i = 'a'; i <= 'z'; i++) {
		encodeTable[i] = (value_type)(26 + (i - 'a'));
	}
	for (i = '0'; i <= '9'; i++) {
		encodeTable[i] = (value_type)(52 + (i - '0'));
	}
	if (base64Url)
	{
		encodeTable[(int)'-'] = 62;
		encodeTable[(int)'_'] = 63;
	}
	else
	{
		encodeTable[(int)'+'] = 62;
		encodeTable[(int)'/'] = 63;
	}
	encodeTable[(int)'='] = 0;

	j = 0;
	k = 0;
	for (;;) {
		value_type a[4], b[4], o[3];
		short padding;
		for (i = 0; i < 4; i++) {
			short c;
		SKIPCHAR:
			if (j < ulInSize) {
				c = pInput[j];
				j++;
			}
			else {
				tmp.resize(k);
				return tmp;
			}

			if (c == 0) {
				/* End of stream */
				tmp.resize(k);
				return tmp;
			}
			if (c == '-')
			{
				comment = true;
			}
			else if ((c == '\r' || c == '\n' || c == '\t' || c == ' '))
			{
				if (c == '\r' || c == '\n')
					comment = false;
				/*
				* Skip the whitespace characters
				*/
				goto SKIPCHAR;
			}
			else if (comment)
			{
				goto SKIPCHAR;
			}

			/*
			* check for invalid characters.  If found, abort.
			*/
			if (encodeTable[c] & 0x80) {
				tmp.resize(0);
				return tmp;
			}
			a[i] = (value_type)c;
			b[i] = (value_type)encodeTable[c];
		}

		/* convert the 4 character group into the original 3 characters */
		o[0] = (value_type)((b[0] << 2) | (b[1] >> 4));
		o[1] = (value_type)((b[1] << 4) | (b[2] >> 2));
		o[2] = (value_type)((b[2] << 6) | b[3]);

		/* determine if there is any padding at the end of the string */
		if (padWithEquals)
		{
			padding = (short)((a[2] == '=' ? 1 : (a[3] == '=' ? 2 : 3)));
		}
		else
		{
			padding = (short)((a[2] == '\0' ? 1 : (a[3] == '\0' ? 2 : 3)));
		}
		for (n = 0; n < padding; n++, k++) {
			if (k >= sz)
				return tmp;
			outbuf[k] = o[n];
		}

		/* if we are out of characters, there is nothing left to do */
		if (i < 1) {
			break;
		}
	}

	tmp.resize(0);
	return tmp;
}
static void encodeOIDPart(tsData &dest, uint32_t value, bool firstPart)
{
	if (value > 127)
	{
		encodeOIDPart(dest, value >> 7, false);
	}
	value &= 127;
	if (!firstPart)
		value |= 128;
	dest += (uint8_t)value;
}
void tsData::FromOIDString(const char* inValue)
{
	uint32_t partNumber = 0;
	uint32_t value = 0;
	char *token = nullptr;
	const char *p;
	tsStringBase str(inValue);

	clear();

	p = strtok_s(str.rawData(), ".", &token);
	while (p != nullptr)
	{
		if (partNumber == 1)
		{
			value = value * 40 + atol(p);
		}
		else
		{
			value = atol(p);
		}
		if (partNumber != 0)
		{
			encodeOIDPart(*this, value, true);
		}

		partNumber++;
		p = strtok_s(nullptr, ".", &token);
	}
}
tsData tsData::substring(size_type start, size_type length) const
{
	if (start >= size() || length == 0)
		return tsData();
	if (start + length >= size())
	{
		length = size() - start;
	}
	return tsData(&c_str()[start], length);
}
tsData& tsData::insert(size_type index, size_type count, char ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsData& tsData::insert(size_type index, char ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsData& tsData::insert(size_type index, const char* s)
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type oldsize = size();
	size_type count = (size_type)strlen(s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsData& tsData::insert(size_type index, const char* s, size_type count)
{
	if (s == nullptr)
		throw std::invalid_argument("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
void tsData::push_back(char ch)
{
	resize(size() + 1, (value_type)ch);
}

tsData &tsData::assign(value_type data)
{
	clear();
	resize(1, data);
	return *this;
}
tsData &tsData::assign(char data)
{
	clear();
	resize(1, (value_type)data);
	return *this;
}
tsData &tsData::assign(int16_t val)
{
	size_type last = 0;

	resize(2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::assign(int32_t val)
{
	size_type last = 0;

	resize(4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::assign(int64_t val)
{
	size_type last = 0;

	resize(8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::assign(uint16_t val)
{
	size_type last = 0;

	resize(2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::assign(uint32_t val)
{
	size_type last = 0;

	resize(4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::assign(uint64_t val)
{
	size_type last = 0;

	resize(8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}

tsData &tsData::append(size_type len, char ch)
{
	resize(size() + len, (value_type)ch);
	return *this;
}
tsData &tsData::append(const char* data, size_type count)
{
	if (data == nullptr)
	{
		return *this;
	}

	tsData::size_type oldUsed = m_used;
	resize(oldUsed + count);
	memcpy(&m_data[oldUsed], data, count * sizeof(value_type));

	return *this;
}
tsData &tsData::append(const char* data)
{
	if (data == nullptr)
	{
		return *this;
	}
	uint32_t count = (size_type)strlen(data);
	tsData::size_type oldUsed = m_used;
	resize(oldUsed + count);
	memcpy(&m_data[oldUsed], data, count * sizeof(value_type));

	return *this;
}
tsData &tsData::append(std::initializer_list<char> list)
{
	size_type pos = size();

	resize(size() + (size_type)list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsData &tsData::append(value_type data)
{
	resize(size() + 1, data);
	return *this;
}
tsData &tsData::append(char data)
{
	resize(size() + 1, (value_type)data);
	return *this;
}
tsData &tsData::append(int16_t val)
{
	size_type last = size();

	resize(size() + 2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::append(int32_t val)
{
	size_type last = size();

	resize(size() + 4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::append(int64_t val)
{
	size_type last = size();

	resize(size() + 8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::append(uint16_t val)
{
	size_type last = size();

	resize(size() + 2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::append(uint32_t val)
{
	size_type last = size();

	resize(size() + 4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsData &tsData::append(uint64_t val)
{
	size_type last = size();

	resize(size() + 8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}

tsData &tsData::operator+= (const char* data) /* zero terminated */
{
	return (*this) += tsData(data);
}
tsData &tsData::operator+= (char data)
{
	tsData::size_type len = 0;
	tsData::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
	return *this;
}
tsData &tsData::operator += (std::initializer_list<char> init)
{
	return append(init);
}
tsData &tsData::operator += (int16_t val)
{
	return append(val);
}
tsData &tsData::operator += (int32_t val)
{
	return append(val);
}
tsData &tsData::operator += (int64_t val)
{
	return append(val);
}
tsData &tsData::operator += (uint16_t val)
{
	return append(val);
}
tsData &tsData::operator += (uint32_t val)
{
	return append(val);
}
tsData &tsData::operator += (uint64_t val)
{
	return append(val);
}

int tsData::compare(const char* s) const
{
	size_type len = (size_type)strlen(s);
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
int tsData::compare(size_type pos1, size_type count1, const char* s) const
{
	return substr(pos1, count1).compare(s);
}
int tsData::compare(size_type pos1, size_type count1, const char* s, size_type count2) const
{
	if (pos1 >= size())
		return -1;

	size_type len = count2;
	size_type availableCount = MIN(size() - pos1, count1);
	size_type count = MIN(availableCount, len);
	int diff = 0;

	diff = memcmp(&m_data[pos1], s, count);
	if (diff != 0)
		return diff;
	if (availableCount > len)
		return 1;
	if (availableCount < len)
		return -1;
	return 0;
}

tsData& tsData::replace(size_type pos, size_type count, const char* s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, const char* s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsData& tsData::replace(size_type pos, size_type count, size_type count2, char ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
void tsData::reverse()
{
	value_type value;

	for (unsigned int i = 0; i < (m_used >> 1); i++)
	{
		value = m_data[i];
		m_data[i] = m_data[m_used - i - 1];
		m_data[m_used - i - 1] = value;
	}
}
tsData &tsData::XOR(const tsData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] ^= value[i];
	}
	return *this;
}
tsData &tsData::AND(const tsData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] &= value[i];
	}
	return *this;
}
tsData &tsData::OR(const tsData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] |= value[i];
	}
	return *this;
}
tsData &tsData::NOT()
{
	for (unsigned int i = 0; i < m_used; i++)
	{
		m_data[i] = ~m_data[i];
	}
	return *this;
}
tsData tsData::right(size_type length) const
{
	tsData tmp = *this;

	if (tmp.size() > length)
		tmp.erase(0, tmp.size() - length);
	return tmp;
}
tsData tsData::left(size_type length) const
{
	tsData tmp = *this;

	if (tmp.size() > length)
		tmp.resize(length);
	return tmp;
}
tsData &tsData::padLeft(size_type length, value_type value)
{
	size_type oldLen = size();

	if (oldLen < length)
	{
		resize(length);
		memmove(&m_data[length - oldLen], &m_data[0], oldLen);
		memset(m_data, value, length - oldLen);
	}
	return *this;
}
tsData &tsData::padRight(size_type length, value_type value)
{
	if (size() < length)
	{
		resize(length, value);
	}
	return *this;
}
tsData &tsData::truncOrPadLeft(size_type length, value_type value)
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
tsStringBase tsData::ToOIDString() const
{
	tsStringBase tmp;
	uint32_t value;
	uint32_t posi = 1;

	if (size() == 0)
		return "";

	value = m_data[0];
	tmp.append((value / 40)).append(".").append((value % 40));
	value = 0;
	while (posi < size())
	{
		value = (value << 7) | (m_data[posi] & 0x7f);
		if ((m_data[posi] & 0x80) == 0)
		{
			tmp.append(".").append(value);
			value = 0;
		}
		posi++;
	}
	if (value != 0)
		return ""; // Bad OID encoding
	return tmp;
}
tsData::UnicodeEncodingType tsData::EncodingType() const
{
	UnicodeEncodingType encoding = encode_Ascii;
	//bool hasBOM = true;

	if (size() > 3)
	{
		const uint8_t *p = (const uint8_t *)m_data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			encoding = encode_Utf1;
		}
		else
		{
			//hasBOM = false;
		}
	}
	else
	{
		//hasBOM = false;
	}
	return encoding;
}

tsData::UnicodeEncodingType tsData::EncodingType(uint8_t *data, uint32_t size) const
{
	UnicodeEncodingType encoding = encode_Ascii;
	//bool hasBOM = true;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			encoding = encode_Utf1;
		}
		else
		{
			//hasBOM = false;
		}
	}
	else
	{
		//hasBOM = false;
	}
	return encoding;
}

tsData tsData::computeBOM(UnicodeEncodingType type)
{
	switch (type)
	{
	case encode_Utf8:
		return tsData({ (uint8_t)0xEF, (uint8_t)0xBB, (uint8_t)0xBF });
	case encode_Utf16BE:
		return tsData({ (uint8_t)0xFE, (uint8_t)0xFF });
	case encode_Utf16LE:
		return tsData({ (uint8_t)0xFF, (uint8_t)0xFE });
	case encode_Utf32BE:
		return tsData({ (uint8_t)0, (uint8_t)0, (uint8_t)0xFE, (uint8_t)0xff });
	case encode_Utf32LE:
		return tsData({ (uint8_t)0xff, (uint8_t)0xFE, (uint8_t)0, (uint8_t)0 });
	case encode_Utf7:
		return tsData({ (uint8_t)0x2B, (uint8_t)0x2F, (uint8_t)0x76 });
	case encode_Utf1:
		return tsData({ (uint8_t)0xF7, (uint8_t)0x64, (uint8_t)0x4C });
	default:
	case encode_Ascii:
		return tsData();
	}
}
tsData& tsData::prependBOM(UnicodeEncodingType type)
{
	tsData tmp(computeBOM(type));

	if (tmp.size() > 0)
		insert(0, tmp);
	return *this;
}
bool tsData::hasEncodingBOM() const
{
	//	UnicodeEncodingType encoding = encode_Ascii;
	bool hasBOM = true;

	if (size() > 3)
	{
		const uint8_t *p = (const uint8_t *)m_data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			//encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			//encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			//encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			//encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			//encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			//encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			//encoding = encode_Utf1;
		}
		else
		{
			hasBOM = false;
		}
	}
	else
	{
		hasBOM = false;
	}
	return hasBOM;
}

bool tsData::hasEncodingBOM(uint8_t *data, uint32_t size) const
{
	//	UnicodeEncodingType encoding = encode_Ascii;
	bool hasBOM = true;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			//			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			//			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			//			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			//			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			//			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			//			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			//			encoding = encode_Utf1;
		}
		else
		{
			hasBOM = false;
		}
	}
	else
	{
		hasBOM = false;
	}
	return hasBOM;
}

uint32_t tsData::BOMByteCount() const
{
	return BOMByteCount(m_data, size());
}

uint32_t tsData::BOMByteCount(uint8_t *data, uint32_t size) const
{
	int count = 0;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			count = 3;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			count = 4;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			count = 4;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			count = 2;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			count = 2;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			count = 3;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			count = 3;
		}
	}
	return count;
}

tsStringBase tsData::ToUtf8String() const
{
	tsStringBase tmp;
	uint32_t destCount;
	UTF8 *dest;
	const UTF16 *src16;
	const UTF32 *src32;
	uint32_t BOMcount = BOMByteCount();

	if (BOMcount > 0)
	{
		switch (EncodingType())
		{
		case encode_Utf16BE:
			src16 = (UTF16*)(m_data + BOMcount);
			destCount = UTF16toUTF8Length(src16, (UTF16*)(m_data + size()), true, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src16 = (UTF16*)(m_data + BOMcount);
			ConvertUTF16toUTF8(&src16, (UTF16*)(m_data + size()), &dest, dest + tmp.size(), true, lenientConversion);
			break;
		case encode_Utf16LE:
			src16 = (UTF16*)(m_data + BOMcount);
			destCount = UTF16toUTF8Length(src16, (UTF16*)(m_data + size()), false, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src16 = (UTF16*)(m_data + BOMcount);
			ConvertUTF16toUTF8(&src16, (UTF16*)(m_data + size()), &dest, dest + tmp.size(), false, lenientConversion);
			break;
		case encode_Utf32BE:
			src32 = (UTF32*)(m_data + BOMcount);
			destCount = UTF32toUTF8Length(src32, (UTF32*)(m_data + size()), true, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src32 = (UTF32*)(m_data + BOMcount);
			ConvertUTF32toUTF8(&src32, (UTF32*)(m_data + size()), &dest, dest + tmp.size(), true, lenientConversion);
			break;
		case encode_Utf32LE:
			src32 = (UTF32*)(m_data + BOMcount);
			destCount = UTF32toUTF8Length(src32, (UTF32*)(m_data + size()), false, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src32 = (UTF32*)(m_data + BOMcount);
			ConvertUTF32toUTF8(&src32, (UTF32*)(m_data + size()), &dest, dest + tmp.size(), false, lenientConversion);
			break;

		default:
		case encode_Ascii:
		case encode_Utf8:
		case encode_Utf7:
		case encode_Utf1:
			tmp.resize(size() - BOMcount);
			memcpy(tmp.rawData(), c_str() + BOMcount, tmp.size());
			break;
		}
	}
	else
	{
		tmp.resize(size());
		memcpy(tmp.rawData(), c_str(), size());
	}
	return tmp;
}

void tsData::AsciiFromString(const tsStringBase& str)
{
	resize((size_type)str.size());
	memcpy(rawData(), str.c_str(), size());
}
void tsData::UTF8FromString(const tsStringBase& str)
{
	size_type len = 0;

	len = (size_type)str.size();
	resize(len);
	memcpy(rawData(), str.data(), len);
}
uint64_t tsData::ToUint64() const
{
	tsData tmp(*this);

	while (tmp.size() < sizeof(uint64_t))
	{
		tmp.insert(0, (value_type)0);
	}
	tmp.resize(sizeof(uint64_t));

#if (BYTE_ORDER == LITTLE_ENDIAN)
	tmp.reverse();
#endif
	return *(uint64_t*)tmp.c_str();
}
tsStringBase tsData::ToHexString() const
{
	size_type count = size();
	size_type i;
	tsStringBase outValue;

	outValue.resize(count * 2);
	outValue.resize(0);

	for (i = 0; i < count; i++)
	{
		value_type val = (*this)[i];

		outValue += ("0123456789ABCDEF")[val >> 4];
		outValue += ("0123456789ABCDEF")[val & 0x0f];
	}
	return outValue;
}
tsStringBase tsData::ToHexStringWithSpaces() const
{
	size_type count = size();
	size_type i;
	tsStringBase outValue;

	outValue.resize(count * 3);
	outValue.resize(0);

	for (i = 0; i < count; i++)
	{
		value_type val = (*this)[i];

		outValue += ("0123456789ABCDEF")[val >> 4];
		outValue += ("0123456789ABCDEF")[val & 0x0f];
		outValue += " ";
	}
	if (outValue.size() > 0)
		outValue.resize(outValue.size() - 1);
	return outValue;
}
tsStringBase tsData::ToHexDump() const
{
	size_type posi = 0, len;
	tsData tmp;
	tsStringBase output, tmpS;

	while (posi < m_used)
	{
		len = m_used - posi;
		if (len > 16)
			len = 16;

		tmpS.Format("%08X", posi);

		tmp = substring(posi, len);
		posi += len;
		output.append(tmpS).append(": ").append(tmp.ToHexStringWithSpaces().PadRight(50, ' '));
		for (size_type i = 0; i < tmp.size(); i++)
		{
			value_type b = tmp[i];
			if (b > 0x1f && b < 0x80)
				output += (char)b;
			else
				output += '.';
		}
		output.append('\n');
	}
	return output;
}
tsStringBase tsData::ToBase64(bool base64Url, bool padWithEquals) const
{
	size_type len;
	tsStringBase outValue;

	outValue.erase();
	if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, m_data, m_used, nullptr, &len))
		outValue.erase();
	else
	{
		outValue.resize(len);
		if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, m_data, m_used, outValue.rawData(), &len) ||
			len == 0)
		{
			outValue.erase();
		}
		outValue.resize(len);
	}
	return outValue;
}
//tsData tsData::PartialDecode(DataStringType type, size_type numberOfBytes, size_type offset)
//{
//	switch (type)
//	{
//	case ASCII:
//		return substring(offset, numberOfBytes);
//	//case OID:
//	//	return substring(offset, numberOfBytes);
//	case HEX:
//		return FromHexString(numberOfBytes, offset);
//	case BASE64:
//		return FromBase64(numberOfBytes, offset);
//	case BASE64URL:
//		return FromBase64(numberOfBytes, offset, true);
//	default:
//		return tsData();
//	}
//}
//tsStringBase tsData::PartialEncode(DataStringType type, size_type numberOfBytes, size_type offset)
//{
//	switch (type)
//	{
//	case ASCII:
//		return substring(offset, numberOfBytes).ToUtf8String();
//	case OID:
//		return substring(offset, numberOfBytes).ToOIDString();
//	case HEX:
//		return substring(offset, numberOfBytes).ToHexString();
//	case BASE64:
//		return substring(offset, numberOfBytes).ToBase64();
//	case BASE64URL:
//		return substring(offset, numberOfBytes).ToBase64(true);
//	default:
//		return "";
//	}
//}
tsData &tsData::increment(value_type step)
{
	difference_type offset = size() - 1;
	int tmp;

	while (offset >= 0)
	{
		tmp = m_data[offset] + step;
		m_data[offset] = (value_type)tmp;
		tmp >>= 8;
		if (tmp == 0)
			break;
		step = (value_type)tmp;
		offset--;
	}

	return *this;
}
tsData &tsData::decrement(value_type step)
{
	difference_type offset = size() - 1;
	int tmp;

	while (offset >= 0)
	{
		tmp = m_data[offset] - step;
		m_data[offset] = (value_type)tmp;
		tmp >>= 8;
		if (tmp == 0)
			break;
		step = (value_type)(-tmp);
		offset--;
	}

	return *this;
}
void  tsData::copyFrom(const tsData &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used);
}

//std::ostream & operator << (std::ostream &Output, const tsData &obj)
//{
//	Output << tsStringBase(obj.ToHexStringWithSpaces()).c_str();
//	return Output;
//}
//std::wostream & operator << (std::wostream &Output, const tsData &obj)
//{
//	Output << obj.ToHexStringWithSpaces().c_str();
//	return Output;
//}


bool operator==(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool operator==(const tsData&& lhs, const tsData&& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool operator!=(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool operator<(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool operator<=(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool operator>(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool operator>=(const tsData& lhs, const tsData& rhs)
{
	return lhs.compare(rhs) >= 0;
}

void swap(tsData &lhs, tsData &rhs)
{
	lhs.swap(rhs);
}


tsData& operator<<(tsData& data, char val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, int8_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, int16_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, int32_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, int64_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, uint8_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, uint16_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, uint32_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, uint64_t val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, const char* val)
{
	return data.append(val);
}
tsData& operator<<(tsData& data, const tsData& val)
{
	return data.append(val);
}
