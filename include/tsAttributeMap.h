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

/*! @file tsAttributeMap.h
 * @brief This file contains the definition of a Named value collection object
*/
#if !defined(__TSATTRIBUTEMAP_H__)
#define __TSATTRIBUTEMAP_H__

#pragma once

/// <summary>name value pair for the tsAttributeMap class</summary>
struct __tsAttributeMapItem
{
	static void *operator new(std::size_t count) {
		return cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return cryptoNew(count);
	}
	static void operator delete(void *ptr) { cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { cryptoDelete(ptr); }

	tsStringBase m_name;
	tsStringBase m_value;
	tsStringBase m_tag;
	bool operator==(const __tsAttributeMapItem& obj) const { return m_name == obj.m_name; }
	bool operator<(const __tsAttributeMapItem& obj) const { return m_name < obj.m_name; }
	__tsAttributeMapItem()
	{}
	__tsAttributeMapItem(const __tsAttributeMapItem& obj) : m_name(obj.m_name), m_tag(obj.m_tag), m_value(obj.m_value)
	{}
	__tsAttributeMapItem(__tsAttributeMapItem&& obj) : m_name(std::move(obj.m_name)), m_tag(std::move(obj.m_tag)), m_value(std::move(obj.m_value))
	{}
	__tsAttributeMapItem& operator=(const __tsAttributeMapItem& obj)
	{
		if (this != &obj)
		{
			m_name = obj.m_name;
			m_tag = obj.m_tag;
			m_value = obj.m_value;
		}
		return *this;
	}
	__tsAttributeMapItem& operator=(__tsAttributeMapItem&& obj)
	{
		if (this != &obj)
		{
			m_name = std::move(obj.m_name);
			m_tag = std::move(obj.m_tag);
			m_value = std::move(obj.m_value);
		}
		return *this;
	}
};

typedef std::vector<__tsAttributeMapItem> tsAttributeMapItemList;

/// <summary>definition of a Named value collection object</summary>
class tsAttributeMap
{
public:
	static void *operator new(std::size_t count) {
		return cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return cryptoNew(count);
	}
	static void operator delete(void *ptr) { cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { cryptoDelete(ptr); }

		/// <summary><para>Initializes an instance of the <see cref="tsAttributeMap" /> class.</para></summary>
	tsAttributeMap();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copy Constructor</summary>
	///
	/// <param name="obj">.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsAttributeMap(const tsAttributeMap &obj);
	tsAttributeMap(tsAttributeMap &&obj);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Destructor.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	~tsAttributeMap();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assignment operator.</summary>
	///
	/// <param name="obj">the object to copy</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsAttributeMap &operator = (const tsAttributeMap &obj);
	tsAttributeMap &operator = (tsAttributeMap &&obj);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the number of name value pairs contained in this container</summary>
	///
	/// <returns>the number of name value pairs</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t count() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the attribute value for the 'index' item.</summary>
	///
	/// <param name="index">the attribute number to return (zero based)</param>
	///
	/// <returns>the attribute value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase item(size_t index) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the attribute value for the named attribute.</summary>
	///
	/// <param name="name">the attribute to return</param>
	///
	/// <returns>the attribute value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase item(const tsStringBase &name) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the named attribute value as an integer.</summary>
	///
	/// <param name="name">		   The attribute name.</param>
	/// <param name="defaultValue">The default value.</param>
	///
	/// <returns>the attribute value as an integer or the default value if the attribute does not exist</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int itemAsNumber(const tsStringBase &name, int defaultValue) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the named attribute value as a boolean.</summary>
	///
	/// <param name="name">		   The attribute name.</param>
	/// <param name="defaultValue">The default value.</param>
	///
	/// <returns>the attribute value as a boolean or the default value if the attribute does not exist</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool itemAsBoolean(const tsStringBase &name, bool defaultValue) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Query if there is an attribute called 'name'.</summary>
	///
	/// <param name="name">The attribute name.</param>
	///
	/// <returns>true if the attribute exists, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool hasItem(const tsStringBase &name) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the attribute name for the specified attribute number</summary>
	///
	/// <param name="index">The attribute number to get</param>
	///
	/// <returns>the attribute name</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase name(size_t index) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds an attribute to the list</summary>
	///
	/// <param name="name">The attribute name</param>
	/// <param name="value">the new attribute value</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool AddItem(const tsStringBase &name, const tsStringBase &value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds an attribute to the list.</summary>
	///
	/// <param name="name"> The attribute name.</param>
	/// <param name="value">the new attribute value.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool AddItem(const tsStringBase &name, int value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Remove all attributes from the list.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void ClearAll();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes the attribute at position 'index'.</summary>
	///
	/// <param name="index">the atribute to remove</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void RemoveItem(size_t index);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes the attribute with the specified name.</summary>
	///
	/// <param name="name">the attribute name to remove</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void RemoveItem(const tsStringBase &name);
	/**
	 * \brief Removes if described by func.
	 *
	 * \param func The function.
	 */
	void remove_if(std::function<bool(const __tsAttributeMapItem& item)> func);
	/**
	 * \brief Foreaches the given function.
	 *
	 * \param [in,out] func The function.
	 */
	void foreach(std::function<void(__tsAttributeMapItem& item)> func);
	/**
	 * \brief Foreaches the given function.
	 *
	 * \param func The function.
	 */
	void foreach(std::function<void(const __tsAttributeMapItem& item)> func) const;
	/**
	 * \brief First value that.
	 *
	 * \param func The function.
	 *
	 * \return A tsStringBase.
	 */
	tsStringBase first_value_that(std::function<bool(const __tsAttributeMapItem& item)> func) const;
	/**
	 * \brief First name that.
	 *
	 * \param func The function.
	 *
	 * \return A tsStringBase.
	 */
	tsStringBase first_name_that(std::function<bool(const __tsAttributeMapItem& item)> func) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts this list to Xml</summary>
	///
	/// <param name="xml">the destination of the xml</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void ToXML(tsStringBase &xml) const;
	/**
	 * \brief Converts the values into fields in the JSONObject.
	 *
	 * \param [in,out] obj The object.
	 */
	tsStringBase tag(size_t index) const;
	void tag(size_t index, const tsStringBase& setTo);
	tsStringBase tag(const tsStringBase &name) const;
	void tag(const tsStringBase &name, const tsStringBase& setTo);
protected:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copies the attributes from the specified list</summary>
	///
	/// <param name="obj">the list to copy</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void copyFrom(const tsAttributeMap &obj);
	void moveFrom(tsAttributeMap &&obj);

protected:
	tsAttributeMapItemList m_list;
};

#endif // __TSATTRIBUTEMAP_H__

