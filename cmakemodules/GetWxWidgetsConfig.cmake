#
# This file is the property of TecSec, Inc. (c) 2017 TecSec, Inc.
# All rights are reserved to TecSec.
#
# This product is protected by one or more of the following
# U.S. patents, as well as pending U.S. patent applications and foreign patents:
# 5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452;
# 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608;
# 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453;
# 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852;
# 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660;
# 7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046.
#
# Written by Roger Butler

if(WIN32 AND MSVC)
	set(wxWidgets_FOUND FALSE)
	set(wxWidgets_INCLUDE_DIRS "")
	set(wxWidgets_LIBRARIES    "")
	set(wxWidgets_LIBRARY_DIRS "")
	set(wxWidgets_CXX_FLAGS    "")
	set(wxWidgets_DEFINITIONS  "")
	set(wxWidgets_BIN_DEBUG    "")
	set(wxWidgets_BIN_RELEASE  "")

	set(wxWidgets_static_FOUND FALSE)
	set(wxWidgets_static_INCLUDE_DIRS "")
	set(wxWidgets_static_LIBRARIES    "")
	set(wxWidgets_static_LIBRARY_DIRS "")
	set(wxWidgets_static_CXX_FLAGS    "")
	set(wxWidgets_static_DEFINITIONS  "")
	set(wxWidgets_static_BIN_DEBUG    "")
	set(wxWidgets_static_BIN_RELEASE  "")

	set(wxProcPart vc${TS_TOOLSET_NUMBER}_${TS_X_PLATFORM})
	set(wxDllFolder ${wxProcPart}_dll)
	set(wxStaticFolder ${wxProcPart}_lib)
	set(wxShortVersion 31)
	set(wxLongVersion 311)
	set(wxVendor _tecsec)
	set(wxUnicodeSuffix u)
	set(wxDebugSuffix d)
	set(wxConfig msw)
	
	set(wxBaseFilesRequired )
	set(wxConfigFilesRequired _adv _core _html)
	set(wxSupportFiles wxjpeg wxpng wxzlib) # wxscintilla wxexpat wxregex wxtiff
	
	set(wxBaseFilesOptional _net _xml)
	set(wxConfigFilesOptional _aui _gl _media _propgrid _qa _ribbon _richtext _stc _webview _xrc)
	
	
	set(wxWidgets_DEFINITIONS 				WXUSINGDLL UNICODE _UNICODE)
	set(wxWidgets_static_DEFINITIONS 		UNICODE _UNICODE)
	set(wxWidgets_DEFINITIONS_DEBUG 		_DEBUG __WXDEBUG__)
	set(wxWidgets_static_DEFINITIONS_DEBUG 	_DEBUG __WXDEBUG__)

	macro(DBG_MSG msg)
		# message(STATUS ${msg})
	endmacro()
	macro(CreateTarget _rightPart _isStatic __libReleasefile __binReleasefile __libDebugfile __binDebugfile)
		if(NOT ${_isStatic} AND wxWidgets_FOUND)
			if(NOT TARGET WxWidgets${_rightPart})
				if(WIN32)
					add_library(WxWidgets${_rightPart} SHARED IMPORTED)
					set_property(TARGET WxWidgets${_rightPart} PROPERTY IMPORTED_LOCATION_RELEASE "${__libReleasefile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY IMPORTED_LOCATION_DEBUG "${__libDebugfile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY INTERFACE_BIN_MODULES_DEBUG "${__binReleasefile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY INTERFACE_BIN_MODULES_RELEASE "${__binDebugfile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY IMPORTED_IMPLIB_DEBUG "${__libDebugfile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY IMPORTED_IMPLIB_RELEASE "${__libReleasefile}")
					set_property(TARGET WxWidgets${_rightPart} PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${wxWidgets_INCLUDE_DIRS}")
				else(WIN32)
					add_library(WxWidgets${_rightPart} SHARED IMPORTED)
					set_target_properties(WxWidgets${_rightPart} PROPERTIES
					IMPORTED_LOCATION_DEBUG "${__libDebugfile}"
					IMPORTED_LOCATION_RELEASE "${__libReleasefile}"
					INTERFACE_INCLUDE_DIRECTORIES "${wxWidgets_INCLUDE_DIRS}")
				endif(WIN32)
				LIST(APPEND WxWidgets_Targets WxWidgets${_rightPart})
			endif()
		endif(NOT ${_isStatic} AND wxWidgets_FOUND)
		if(${_isStatic} AND wxWidgets_static_FOUND)
			if(NOT TARGET WxWidgets_static${_rightPart})
				if(WIN32)
					add_library(WxWidgets_static${_rightPart} STATIC IMPORTED)
					set_property(TARGET WxWidgets_static${_rightPart} PROPERTY IMPORTED_LOCATION_DEBUG "${__libDebugfile}")
					set_property(TARGET WxWidgets_static${_rightPart} PROPERTY IMPORTED_LOCATION_RELEASE "${__libReleasefile}")
					set_property(TARGET WxWidgets_static${_rightPart} PROPERTY IMPORTED_IMPLIB_DEBUG "${__libDebugfile}")
					set_property(TARGET WxWidgets_static${_rightPart} PROPERTY IMPORTED_IMPLIB_RELEASE "${__libReleasefile}")
					set_property(TARGET WxWidgets_static${_rightPart} PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${wxWidgets_static_INCLUDE_DIRS}")
				else(WIN32)
					add_library(WxWidgets_static${_rightPart} STATIC IMPORTED)
					set_target_properties(WxWidgets_static${_rightPart} PROPERTIES
					IMPORTED_LOCATION_DEBUG "${__libDebugfile}"
					IMPORTED_LOCATION_RELEASE "${__libReleasefile}"
					INTERFACE_INCLUDE_DIRECTORIES "${wxWidgets_static_INCLUDE_DIRS}")
				endif(WIN32)
				LIST(APPEND WxWidgets_static_Targets WxWidgets_static${_rightPart})
			endif()
		endif(${_isStatic} AND wxWidgets_static_FOUND)
	endmacro()
	macro(ResolveFiles _leftPart _rightPart _staticPart _debugPart _required _isStatic)
		set(__libReleasefile )
		set(__binReleasefile )
		set(__libDebugfile )
		set(__binDebugfile )

		if(EXISTS ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_rightPart}.lib)
			set(__libReleasefile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_rightPart}.lib)
			set(__binReleasefile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxLongVersion}${wxUnicodeSuffix}${_rightPart}_${wxProcPart}${wxVendor}${CMAKE_SHARED_MODULE_SUFFIX})
			if(NOT WX${_staticPart}_USE_REL_AND_DBG)
				set(__libDebugfile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_rightPart}.lib)
				set(__binDebugfile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxLongVersion}${wxUnicodeSuffix}${_rightPart}_${wxProcPart}${wxVendor}${CMAKE_SHARED_MODULE_SUFFIX})
			endif()
		elseif(_required)
			DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because WX_ROOT_DIR=${WX_ROOT_DIR} has no ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_rightPart}.lib")
			set(wxWidgets${_staticPart}_FOUND FALSE)
		endif()

		if(WX${_staticPart}_USE_REL_AND_DBG)
			if(EXISTS ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_debugPart}${_rightPart}.lib)
				set(__libDebugfile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_debugPart}${_rightPart}.lib)
				set(__binDebugfile ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxLongVersion}${wxUnicodeSuffix}${_debugPart}${_rightPart}_${wxProcPart}${wxVendor}${CMAKE_SHARED_MODULE_SUFFIX})
			elseif(_required)
				DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because WX_ROOT_DIR=${WX_ROOT_DIR} has no ${WX${_staticPart}_LIB_DIR}/wx${_leftPart}${wxShortVersion}${wxUnicodeSuffix}${_debugPart}${_rightPart}.lib")
				set(wxWidgets${_staticPart}_FOUND FALSE)
			endif()
		endif()
			
		CreateTarget("${_rightPart}" "${_isStatic}" "${__libReleasefile}" "${__binReleasefile}" "${__libDebugfile}" "${__binDebugfile}")
	endmacro()
	macro(FindWxTree pathPart _staticPart _debugPart _isStatic)
		find_path(wxWidgets${_staticPart}_LIB_DIR
			NAMES
				msw/wx/setup.h
				mswu/wx/setup.h
				mswuniv/wx/setup.h
				mswunivu/wx/setup.h
			PATHS
				${WX_ROOT_DIR}/lib/${pathPart}
			DOC "Path to wxWidgets libraries"
			NO_DEFAULT_PATH
			)
		If(NOT WX${_staticPart}_LIB_DIR STREQUAL wxWidgets${_staticPart}_LIB_DIR)
		  set(WX${_staticPart}_LIB_DIR ${wxWidgets${_staticPart}_LIB_DIR}) # CACHE INTERNAL "wxWidgets${_staticPart}_LIB_DIR")
		  # WX_CLEAR_ALL_DBG_LIBS()
		  # WX_CLEAR_ALL_REL_LIBS()
		endif()
		set(WX${_staticPart}_CONFIGURATION_LIST )
		foreach(CFG ${wxConfig}${wxUnicodeSuffix})
			set(WX${_staticPart}_${CFG}_FOUND FALSE)
			if(EXISTS ${WX_ROOT_DIR}/lib/${pathPart}/${CFG})
				list(APPEND WX${_staticPart}_CONFIGURATION_LIST ${CFG})
				set(WX${_staticPart}_${CFG}_FOUND TRUE)
				set(WX${_staticPart}_CONFIGURATION ${CFG})
				if(EXISTS ${WX_ROOT_DIR}/lib/${pathPart}/${CFG}${_debugPart})
					set(WX${_staticPart}_${CFG}${_debugPart}_FOUND TRUE)
				else()
					set(WX${_staticPart}_${CFG}${_debugPart}_FOUND FALSE)
				endif()
			endif()
			# message(STATUS "WX${_staticPart}_${CFG}_FOUND = ${WX${_staticPart}_${CFG}_FOUND}")
			# message(STATUS "WX${_staticPart}_${CFG}${_debugPart}_FOUND = ${WX${_staticPart}_${CFG}${_debugPart}_FOUND}")
		endforeach()

		if(WX${_staticPart}_CONFIGURATION)
			set(wxWidgets${_staticPart}_FOUND TRUE)

			set(wxWidgets${_staticPart}_CONFIGURATION ${WX${_staticPart}_CONFIGURATION}) # CACHE STRING "Set wxWidgets configuration (${WX${_staticPart}_CONFIGURATION_LIST})" FORCE)
# message(STATUS "WX${_staticPart}_CONFIGURATION = ${WX${_staticPart}_CONFIGURATION}")
# message(STATUS "WX${_staticPart}_${wxWidgets${_staticPart}_CONFIGURATION}d_FOUND = ${WX${_staticPart}_${wxWidgets${_staticPart}_CONFIGURATION}d_FOUND}")

			if(WX${_staticPart}_${wxWidgets${_staticPart}_CONFIGURATION}d_FOUND)
				set(WX${_staticPart}_USE_REL_AND_DBG TRUE)
			else()
				set(WX${_staticPart}_USE_REL_AND_DBG FALSE)
			endif()
# message(STATUS "WX${_staticPart}_USE_REL_AND_DBG = ${WX${_staticPart}_USE_REL_AND_DBG}")
			if(EXISTS ${WX${_staticPart}_LIB_DIR}/${wxWidgets${_staticPart}_CONFIGURATION}/wx/setup.h)
				set(wxWidgets${_staticPart}_INCLUDE_DIRS ${WX${_staticPart}_LIB_DIR}/${wxWidgets${_staticPart}_CONFIGURATION})
			else()
				DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because ${WX${_staticPart}_LIB_DIR}/${wxWidgets${_staticPart}_CONFIGURATION}/wx/setup.h does not exists.")
				set(wxWidgets${_staticPart}_FOUND FALSE)
			endif()

			if(EXISTS ${WX_ROOT_DIR}/include/wx/wx.h)
				list(APPEND wxWidgets${_staticPart}_INCLUDE_DIRS ${WX_ROOT_DIR}/include)
			else()
				DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because WX_ROOT_DIR=${WX_ROOT_DIR} has no ${WX_ROOT_DIR}/include/wx/wx.h")
				set(wxWidgets${_staticPart}_FOUND FALSE)
			endif()
    
			ResolveFiles(base "" "${_staticPart}" "${_debugPart}" ON ${_isStatic})
			
			foreach(__tmp ${wxBaseFilesRequired})
				ResolveFiles(base "${__tmp}" "${_staticPart}" "${_debugPart}" ON ${_isStatic})
			endforeach()
			foreach(__tmp ${wxBaseFilesOptional})
				ResolveFiles(base "${__tmp}" "${_staticPart}" "${_debugPart}" OFF ${_isStatic})
			endforeach()
			foreach(__tmp ${wxConfigFilesRequired})
				ResolveFiles(${wxConfig} "${__tmp}" "${_staticPart}" "${_debugPart}" ON ${_isStatic})
			endforeach()
			foreach(__tmp ${wxConfigFilesOptional})
				ResolveFiles(${wxConfig} "${__tmp}" "${_staticPart}" "${_debugPart}" OFF ${_isStatic})
			endforeach()
			if(${_isStatic})
				foreach(__tmp ${wxSupportFiles})
					set(__libReleasefile )
					set(__libDebugfile )

					if(EXISTS ${WX${_staticPart}_LIB_DIR}/${__tmp}.lib)
						set(__libReleasefile ${WX${_staticPart}_LIB_DIR}/${__tmp}.lib)
						if(NOT WX${_staticPart}_USE_REL_AND_DBG)
							set(__libDebugfile ${WX${_staticPart}_LIB_DIR}/${__tmp}.lib)
						endif()
					else()
						DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because WX_ROOT_DIR=${WX_ROOT_DIR} has no ${WX${_staticPart}_LIB_DIR}/${__tmp}.lib")
						set(wxWidgets${_staticPart}_FOUND FALSE)
					endif()

					if(WX${_staticPart}_USE_REL_AND_DBG)
						if(EXISTS ${WX${_staticPart}_LIB_DIR}/${__tmp}${_debugPart}.lib)
							set(__libDebugfile ${WX${_staticPart}_LIB_DIR}/${__tmp}${_debugPart}.lib)
						else()
							DBG_MSG("wxWidgets${_staticPart}_FOUND FALSE because WX_ROOT_DIR=${WX_ROOT_DIR} has no ${WX${_staticPart}_LIB_DIR}/${__tmp}${_debugPart}.lib")
							set(wxWidgets${_staticPart}_FOUND FALSE)
						endif()
					endif()
					if(wxWidgets${_staticPart}_FOUND)
							CreateTarget(${__tmp} ON "${__libReleasefile}" "" "${__libDebugfile}" "")
					endif(wxWidgets${_staticPart}_FOUND)
				endforeach()
			endif(${_isStatic})
		endif()

	endmacro()
	
  find_path(wxWidgets_ROOT_DIR
    NAMES include/wx/wx.h
    PATHS
      ENV wxWidgets_ROOT_DIR
      ENV WXWIN
      "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\wxWidgets_is1;Inno Setup: App Path]"  # WX 2.6.x
      C:/
      D:/
      ENV ProgramFiles
    PATH_SUFFIXES
      wxWidgets-3.1.1
      wxWidgets-3.1.0
      wxWidgets-3.0.1
      wxWidgets-3.0.0
      wxWidgets-2.9.5
      wxWidgets-2.9.4
      wxWidgets-2.9.3
      wxWidgets-2.9.2
      wxWidgets-2.9.1
      wxWidgets-2.9.0
      wxWidgets-2.8.9
      wxWidgets-2.8.8
      wxWidgets-2.8.7
      wxWidgets-2.8.6
      wxWidgets-2.8.5
      wxWidgets-2.8.4
      wxWidgets-2.8.3
      wxWidgets-2.8.2
      wxWidgets-2.8.1
      wxWidgets-2.8.0
      wxWidgets-2.7.4
      wxWidgets-2.7.3
      wxWidgets-2.7.2
      wxWidgets-2.7.1
      wxWidgets-2.7.0
      wxWidgets-2.7.0-1
      wxWidgets-2.6.4
      wxWidgets-2.6.3
      wxWidgets-2.6.2
      wxWidgets-2.6.1
      wxWidgets-2.5.4
      wxWidgets-2.5.3
      wxWidgets-2.5.2
      wxWidgets-2.5.1
      wxWidgets
    DOC "wxWidgets base/installation directory"
    )
	
  # If wxWidgets_ROOT_DIR changed, clear lib dir.
  if(NOT WX_ROOT_DIR STREQUAL wxWidgets_ROOT_DIR)
    set(WX_ROOT_DIR ${wxWidgets_ROOT_DIR}) # CACHE INTERNAL "wxWidgets_ROOT_DIR")
    set(wxWidgets_LIB_DIR "wxWidgets_LIB_DIR-NOTFOUND") # CACHE PATH "Cleared." FORCE)
    set(wxWidgets_static_LIB_DIR "wxWidgets_static_LIB_DIR-NOTFOUND") # CACHE PATH "Cleared." FORCE)
  endif()

  FindWxTree(${wxDllFolder} "" ${wxDebugSuffix} OFF)
  FindWxTree(${wxStaticFolder} "_static" ${wxDebugSuffix} ON)
  
	DBG_MSG("
	wxWidgets_LIB_DIR             = ${wxWidgets_LIB_DIR}
	wxWidgets_FOUND               = ${wxWidgets_FOUND}
	wxWidgets_INCLUDE_DIRS        = ${wxWidgets_INCLUDE_DIRS}
	WxWidgets_Targets             = ${WxWidgets_Targets}
	wxWidgets_LIBRARY_DIRS        = ${wxWidgets_LIBRARY_DIRS}
	wxWidgets_CXX_FLAGS           = ${wxWidgets_CXX_FLAGS}
	wxWidgets_DEFINITIONS         = ${wxWidgets_DEFINITIONS}
	WX_USE_REL_AND_DBG            = ${WX_USE_REL_AND_DBG}

	wxWidgets_static_LIB_DIR             = ${wxWidgets_static_LIB_DIR}
	wxWidgets_static_FOUND               = ${wxWidgets_static_FOUND}
	wxWidgets_static_INCLUDE_DIRS        = ${wxWidgets_static_INCLUDE_DIRS}
	WxWidgets_static_Targets             = ${WxWidgets_static_Targets}
	wxWidgets_static_LIBRARY_DIRS        = ${wxWidgets_static_LIBRARY_DIRS}
	wxWidgets_static_CXX_FLAGS           = ${wxWidgets_static_CXX_FLAGS}
	wxWidgets_static_DEFINITIONS         = ${wxWidgets_static_DEFINITIONS}
	WX_static_USE_REL_AND_DBG            = ${WX_static_USE_REL_AND_DBG}")
	
else()
	set(wxWidgets_EXCLUDE_COMMON_LIBRARIES ON)
	find_package(wxWidgets COMPONENTS core base adv html )
endif()

