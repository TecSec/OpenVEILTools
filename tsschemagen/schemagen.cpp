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

tsStringBase gOutputPath;
tsStringBase gPrefix;
tsStringBase gBuildType;
bool useC = false;

static struct ts_getopt_option long_options[] =
{
    { "output",  ts_required_argument, 0, 'o' },
    { "build",  ts_required_argument, 0, 'b' },
    { "prefix",  ts_required_argument, 0, 'p' },
    { "help", ts_no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

static void Usage()
{
	printf("USAGE: \n   -c  C output\n   -o=dir or --output=dir \n   -p=prefix or --prefix=prefix \n   -b=buildType or --build=buildtype    - where buildtype is MSSQL, SQLITE, ORACLE, MYSQL, SQL, H, CPP, CODE, ALL\n   fileToProcess [filetoprocess]*\n");
}

static std::vector<tsStringBase> SplitString(const tsStringBase& src, const tsStringBase& splitOnString)
{
	std::vector<tsStringBase> parts;
	char *start;
	tsStringBase m_sql(src);

	start = (char *)m_sql.c_str();
	while (start != NULL && *start)
	{
		char *end = strstr(start, splitOnString.c_str());

		if (end != NULL)
		{
			*end = 0;
		}

		parts.push_back(start);

		if (end != NULL)
			start = end + splitOnString.size();
		else
			start = NULL;
	}
	return parts;
}
static void SendOutputToFiles(std::shared_ptr<SQLHelper> builder, std::vector<tsStringBase> fileNames, const tsStringBase& schemaFilename, SQLHelper::SchemaPartType schemaPart)
{
	tsStringBase sql;

	sql = builder->BuildSchema(schemaFilename, schemaPart);

	std::vector<tsStringBase> parts = SplitString(sql, "<<<<NEXT FILE>>>>");

	for (int i = 0; i < (int)fileNames.size(); i++)
	{
		if ((int)parts.size() > i)
			xp_WriteText(fileNames[i], parts[i]);
	}
}
static tsStringBase ToLower(const tsStringBase& value)
{
	tsStringBase tmp(value);

	tmp.ToLower();
	return tmp;
}
static bool ProcessFile(const char *filename)
{

	std::shared_ptr<SQLHelper> builder;
	std::vector<tsStringBase> fileNames;

	try
	{
		if (gBuildType == "MSSQL" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new SqlServerHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "SQLITE" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new SqliteHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "ORACLE" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new OracleHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "MYSQL" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new MySqlHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "H" || gBuildType == "CPP" || gBuildType == "C" || gBuildType == "CODE" || gBuildType == "ALL")
		{
            if (useC)
            {
                builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new CHelper(gBuildType != "C", gBuildType != "H")));
                fileNames.clear();
                if (gBuildType != "C")
                    fileNames.push_back(gOutputPath + gPrefix + "_Data.h");
                if (gBuildType != "H")
                    fileNames.push_back(gOutputPath + gPrefix + "_Data.c");
            }
            else
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new CppHelper(gBuildType != "CPP", gBuildType != "H")));
			fileNames.clear();
			if (gBuildType != "CPP")
				fileNames.push_back(gOutputPath + gPrefix + "_Data.h");
			if (gBuildType != "H")
				fileNames.push_back(gOutputPath + gPrefix + "_Data.cpp");
            }
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);
		}
		printf("The output file is stored in '%s'.\n", gOutputPath.c_str());
		return true;
	}
	catch (std::exception& ex)
	{
		printf("ERROR:  %s\n", ex.what());
		return false;
	}
}

int main(int argc, const char* argv[])
{
    int c;
    int option_index;

#if defined(_DEBUG) && defined(_WIN32)
    //_CrtSetBreakAlloc(268903);
    //_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); //  _CRTDBG_CHECK_ALWAYS_DF _CRTDBG_CHECK_EVERY_128_DF | _CRTDBG_DELAY_FREE_MEM_DF | |  
    //TS_EnableHeapCheckOnEachAllocOrFree();
#endif

    if (argc == 1)
			{
				Usage();
        return 1;
			}

    while (1)
			{
        /* getopt_long stores the option index here. */
        option_index = 0;

        c = ts_getopt_long(argc, argv, "cChHo:b:p:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            printf("option %s", long_options[option_index].name);
            if (ts_get_optarg())
                printf(" with arg %s", ts_get_optarg());
            printf("\n");
            break;

        case 'c':
        case 'C':
                useC = true;
            break;

        case 'b':
            gBuildType = ts_get_optarg();
            break;
        case 'p':
            gPrefix = ts_get_optarg();
            break;
        case 'o':
            gOutputPath = ts_get_optarg();
            break;
        case '?':
        case 'h':
            Usage();
            return 0;

        default:
            return(1);
		}
	}

    /* Print any remaining command line arguments (not options). */
    if (ts_get_optind() >= argc)
	{
		Usage();
		return 1;
	}

	if (gOutputPath.size() == 0)
	{
#ifdef _WIN32
		gOutputPath = "C:\\TecSec\\Logs\\";
#else
		gOutputPath = "~/";
#endif
	}

	if (gOutputPath[gOutputPath.size() - 1] != XP_PATH_SEP_CHAR)
	{
		gOutputPath += XP_PATH_SEP_STR;
	}

	if (!XP_FileExists(gOutputPath.c_str()))
	{
		XP_CreateDirectory(gOutputPath.c_str(), false);
	}

	gBuildType.ToUpper();
	if (gBuildType.size() == 0)
		gBuildType = "ALL";

	if (gBuildType != "MSSQL" && gBuildType != "SQLITE" && gBuildType != "ORACLE" && gBuildType != "MYSQL" && gBuildType != "SQL" && gBuildType != "H" && gBuildType != "CPP" && gBuildType != "CODE" && gBuildType != "ALL")
	{
		printf("The buildtype is not valid.\n");
		return 1;
	}

	if (gPrefix.size() == 0)
	{
		printf("You need to specify the prefix.\n");
		return 1;
	}

	try
	{
		for (int i = ts_get_optind(); i < argc; i++)
		{
			if (!ProcessFile(argv[i]))
				return 1;
		}
	}
	catch (std::exception& e)
	{
		printf("ERROR:  %s\n", e.what());
		return 1;
	}


	return 0;
}

