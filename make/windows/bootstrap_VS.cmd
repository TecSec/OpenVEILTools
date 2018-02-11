@echo off
rem	Copyright (c) 2017, TecSec, Inc.
rem
rem	Redistribution and use in source and binary forms, with or without
rem	modification, are permitted provided that the following conditions are met:
rem	
rem		* Redistributions of source code must retain the above copyright
rem		  notice, this list of conditions and the following disclaimer.
rem		* Redistributions in binary form must reproduce the above copyright
rem		  notice, this list of conditions and the following disclaimer in the
rem		  documentation and/or other materials provided with the distribution.
rem		* Neither the name of TecSec nor the names of the contributors may be
rem		  used to endorse or promote products derived from this software 
rem		  without specific prior written permission.
rem		 
rem	ALTERNATIVELY, provided that this notice is retained in full, this product
rem	may be distributed under the terms of the GNU General Public License (GPL),
rem	in which case the provisions of the GPL apply INSTEAD OF those given above.
rem		 
rem	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
rem	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
rem	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
rem	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
rem	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
rem	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
rem	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
rem	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
rem	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
rem	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
rem
rem Written by Roger Butler

set COMPILERVERSION=%1

if "%COMPILERVERSION%"=="" set COMPILERVERSION=14
if "%COMPILERVERSION%"=="2013" set COMPILERVERSION=12
if "%COMPILERVERSION%"=="2015" set COMPILERVERSION=14
if "%COMPILERVERSION%"=="2017" set COMPILERVERSION=15


SETLOCAL ENABLEDELAYEDEXPANSION

if not exist ..\..\Build md ..\..\Build

pushd ..\..\Build

echo ============================================================================
  if not exist vsdebug-vc%COMPILERVERSION%-x86 md vsdebug-vc%COMPILERVERSION%-x86
  pushd vsdebug-vc%COMPILERVERSION%-x86
  echo @echo off > resetenv.cmd
  echo if "%%BASEPATH%%"=="" set BASEPATH=%%path%% >> resetenv.cmd
  echo set PATH=%%BASEPATH%% >> resetenv.cmd
  echo if "%%BASELIB%%"=="" set BASELIB=%%LIB%% >> resetenv.cmd
  echo set LIB=%%BASELIB%% >> resetenv.cmd
  echo if "%%BASELIBPATH%%"=="" set BASELIBPATH=%%LIBPATH%% >> resetenv.cmd
  echo set LIBPATH=%%BASELIBPATH%% >> resetenv.cmd
  echo if "%%BASEINCLUDE%%"=="" set BASEINCLUDE=%%INCLUDE%% >> resetenv.cmd
  echo set INCLUDE=%%BASEINCLUDE%% >> resetenv.cmd
  echo set WD=%%CD%% >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall" x86 >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall" x86 >> resetenv.cmd
  echo CD /D %%WD%% >> resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Debug -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio %COMPILERVERSION%" ..\..
  call :makefolderscripts Win32 Debug
  popd

echo ============================================================================
  if not exist vsrelease-vc%COMPILERVERSION%-x86 md vsrelease-vc%COMPILERVERSION%-x86
  pushd vsrelease-vc%COMPILERVERSION%-x86
  echo @echo off > resetenv.cmd
  echo if "%%BASEPATH%%"=="" set BASEPATH=%%path%% >> resetenv.cmd
  echo set PATH=%%BASEPATH%% >> resetenv.cmd
  echo if "%%BASELIB%%"=="" set BASELIB=%%LIB%% >> resetenv.cmd
  echo set LIB=%%BASELIB%% >> resetenv.cmd
  echo if "%%BASELIBPATH%%"=="" set BASELIBPATH=%%LIBPATH%% >> resetenv.cmd
  echo set LIBPATH=%%BASELIBPATH%% >> resetenv.cmd
  echo if "%%BASEINCLUDE%%"=="" set BASEINCLUDE=%%INCLUDE%% >> resetenv.cmd
  echo set INCLUDE=%%BASEINCLUDE%% >> resetenv.cmd
  echo set WD=%%CD%% >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall" x86 >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall" x86 >> resetenv.cmd
  echo CD /D %%WD%% >> resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Release -DCMAKE_BUILD_TYPE=Release -G "Visual Studio %COMPILERVERSION%" ..\..
  call :makefolderscripts Win32 Release
  popd

echo ============================================================================
  if not exist vsdebug-vc%COMPILERVERSION%-x64 md vsdebug-vc%COMPILERVERSION%-x64
  pushd vsdebug-vc%COMPILERVERSION%-x64
  echo @echo off > resetenv.cmd
  echo if "%%BASEPATH%%"=="" set BASEPATH=%%path%% >> resetenv.cmd
  echo set PATH=%%BASEPATH%% >> resetenv.cmd
  echo if "%%BASELIB%%"=="" set BASELIB=%%LIB%% >> resetenv.cmd
  echo set LIB=%%BASELIB%% >> resetenv.cmd
  echo if "%%BASELIBPATH%%"=="" set BASELIBPATH=%%LIBPATH%% >> resetenv.cmd
  echo set LIBPATH=%%BASELIBPATH%% >> resetenv.cmd
  echo if "%%BASEINCLUDE%%"=="" set BASEINCLUDE=%%INCLUDE%% >> resetenv.cmd
  echo set INCLUDE=%%BASEINCLUDE%% >> resetenv.cmd
  echo set WD=%%CD%% >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall" amd64 >> resetenv.cmd
  echo CD /D %%WD%% >> resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Debug -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio %COMPILERVERSION% Win64" ..\..
  call :makefolderscripts x64 Debug
  popd
  
echo ============================================================================
  if not exist vsrelease-vc%COMPILERVERSION%-x64 md vsrelease-vc%COMPILERVERSION%-x64
  pushd vsrelease-vc%COMPILERVERSION%-x64
  echo @echo off > resetenv.cmd
  echo if "%%BASEPATH%%"=="" set BASEPATH=%%path%% >> resetenv.cmd
  echo set PATH=%%BASEPATH%% >> resetenv.cmd
  echo if "%%BASELIB%%"=="" set BASELIB=%%LIB%% >> resetenv.cmd
  echo set LIB=%%BASELIB%% >> resetenv.cmd
  echo if "%%BASELIBPATH%%"=="" set BASELIBPATH=%%LIBPATH%% >> resetenv.cmd
  echo set LIBPATH=%%BASELIBPATH%% >> resetenv.cmd
  echo if "%%BASEINCLUDE%%"=="" set BASEINCLUDE=%%INCLUDE%% >> resetenv.cmd
  echo set INCLUDE=%%BASEINCLUDE%% >> resetenv.cmd
  echo set WD=%%CD%% >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  if exist "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall.bat" echo call "!VS%COMPILERVERSION%0COMNTOOLS!..\..\vc\Auxiliary\Build\vcvarsall" amd64 >> resetenv.cmd
  echo CD /D %%WD%% >> resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Release -DCMAKE_BUILD_TYPE=Release -G "Visual Studio %COMPILERVERSION% Win64" ..\..
  call :makefolderscripts x64 Release
  popd

  
echo @echo off > buildall-vc%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > buildall-vc%COMPILERVERSION%.cmd
echo for %%%%i in (debug release) do ( >> buildall-vc%COMPILERVERSION%.cmd
echo    for %%%%j in (vc%COMPILERVERSION%) do ( >> buildall-vc%COMPILERVERSION%.cmd
echo      for %%%%k in (x86 x64) do ( >> buildall-vc%COMPILERVERSION%.cmd
echo 		pushd vs%%%%i-%%%%j-%%%%k >> buildall-vc%COMPILERVERSION%.cmd
echo        call resetenv >> buildall-vc%COMPILERVERSION%.cmd
echo        call cmake . >> buildall-vc%COMPILERVERSION%.cmd
echo        call install.cmd >> buildall-vc%COMPILERVERSION%.cmd
echo        if errorlevel 1 ( >> buildall-vc%COMPILERVERSION%.cmd
echo           popd  >> buildall-vc%COMPILERVERSION%.cmd
echo		   goto :eof >> buildall-vc%COMPILERVERSION%.cmd
echo		)  >> buildall-vc%COMPILERVERSION%.cmd
echo        if not errorlevel 0 ( >> buildall-vc%COMPILERVERSION%.cmd
echo           popd  >> buildall-vc%COMPILERVERSION%.cmd
echo		   goto :eof >> buildall-vc%COMPILERVERSION%.cmd
echo		)  >> buildall-vc%COMPILERVERSION%.cmd
echo 		popd >> buildall-vc%COMPILERVERSION%.cmd
echo 	 ) >> buildall-vc%COMPILERVERSION%.cmd
echo    ) >> buildall-vc%COMPILERVERSION%.cmd
echo ) >> buildall-vc%COMPILERVERSION%.cmd

echo @echo off > buildrelease-vc%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > buildrelease-vc%COMPILERVERSION%.cmd
echo for %%%%i in (release) do ( >> buildrelease-vc%COMPILERVERSION%.cmd
echo    for %%%%j in (vc%COMPILERVERSION%) do ( >> buildrelease-vc%COMPILERVERSION%.cmd
echo      for %%%%k in (x86 x64) do ( >> buildrelease-vc%COMPILERVERSION%.cmd
echo 		pushd vs%%%%i-%%%%j-%%%%k >> buildrelease-vc%COMPILERVERSION%.cmd
echo        call clean.cmd >> buildrelease-vc%COMPILERVERSION%.cmd
echo        call resetenv >> buildrelease-vc%COMPILERVERSION%.cmd
echo        call cmake . >> buildrelease-vc%COMPILERVERSION%.cmd
echo        call install.cmd >> buildrelease-vc%COMPILERVERSION%.cmd
echo        if errorlevel 1 ( >> buildrelease-vc%COMPILERVERSION%.cmd
echo           popd  >> buildrelease-vc%COMPILERVERSION%.cmd
echo		   goto :eof >> buildrelease-vc%COMPILERVERSION%.cmd
echo		)  >> buildrelease-vc%COMPILERVERSION%.cmd
echo        if not errorlevel 0 ( >> buildrelease-vc%COMPILERVERSION%.cmd
echo           popd  >> buildrelease-vc%COMPILERVERSION%.cmd
echo		   goto :eof >> buildrelease-vc%COMPILERVERSION%.cmd
echo		)  >> buildrelease-vc%COMPILERVERSION%.cmd
echo 		popd >> buildrelease-vc%COMPILERVERSION%.cmd
echo 	 ) >> buildrelease-vc%COMPILERVERSION%.cmd
echo    ) >> buildrelease-vc%COMPILERVERSION%.cmd
echo ) >> buildrelease-vc%COMPILERVERSION%.cmd

echo @echo off > cleanall-vc%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > cleanall-vc%COMPILERVERSION%.cmd
echo for %%%%i in (release debug) do ( >> cleanall-vc%COMPILERVERSION%.cmd
echo    for %%%%j in (vc%COMPILERVERSION%) do ( >> cleanall-vc%COMPILERVERSION%.cmd
echo      for %%%%k in (x86 x64) do ( >> cleanall-vc%COMPILERVERSION%.cmd
echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanall-vc%COMPILERVERSION%.cmd
echo        call clean.cmd >> cleanall-vc%COMPILERVERSION%.cmd
echo 		popd >> cleanall-vc%COMPILERVERSION%.cmd
echo 	 ) >> cleanall-vc%COMPILERVERSION%.cmd
echo    ) >> cleanall-vc%COMPILERVERSION%.cmd
echo ) >> cleanall-vc%COMPILERVERSION%.cmd

echo @echo off > cleanrelease-vc%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > cleanrelease-vc%COMPILERVERSION%.cmd
echo for %%%%i in (release) do ( >> cleanrelease-vc%COMPILERVERSION%.cmd
echo    for %%%%j in (vc%COMPILERVERSION%) do ( >> cleanrelease-vc%COMPILERVERSION%.cmd
echo      for %%%%k in (x86 x64) do ( >> cleanrelease-vc%COMPILERVERSION%.cmd
echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanrelease-vc%COMPILERVERSION%.cmd
echo        call clean.cmd >> cleanrelease-vc%COMPILERVERSION%.cmd
echo 		popd >> cleanrelease-vc%COMPILERVERSION%.cmd
echo 	 ) >> cleanrelease-vc%COMPILERVERSION%.cmd
echo    ) >> cleanrelease-vc%COMPILERVERSION%.cmd
echo ) >> cleanrelease-vc%COMPILERVERSION%.cmd

popd

goto :eof

:makefolderscripts
  echo @echo off > build.cmd
  echo call resetenv >> build.cmd
  echo call msbuild /m /p:Configuration=%2 /p:Platform=%1 ALL_BUILD.vcxproj >> build.cmd
  echo @echo off > install.cmd
  echo call resetenv >> install.cmd
  echo call msbuild /m /p:Configuration=%2 /p:Platform=%1 INSTALL.vcxproj >> install.cmd
  echo @echo off > clean.cmd
  echo call resetenv >> clean.cmd
  echo call msbuild /m /target:clean /p:Configuration=%2 /p:Platform=%1 ALL_BUILD.vcxproj >> clean.cmd
  exit /b
  
  