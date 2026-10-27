#pragma once
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <mutex>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <winternl.h>
#include <cstdint>
#include <functional>
#include <dia2.h>
#include <diacreate.h>
#include <atlbase.h>
#include <string>
#include <memory>
#include <utility>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "ntdll.lib")

#include <dependencies/ia32/include.h>
#include <dependencies/oxorany/include.h>

#include <workspace/utility/logger.hxx>
#include <workspace/utility/utility.hxx>

#include <impl/pdb/pdb.hxx>

#include <workspace/core/service/bytes.h>
#include <workspace/core/service/service.hxx>
#include <workspace/core/service/startup.hxx>

#include <workspace/core/service/driver/driver.hxx>

#include <workspace/core/memory/paging/paging.hxx>
#include <workspace/core/memory/syscall/syscall.hxx>

#include <workspace/utility/exit.hxx>

#include <workspace/core/spoof/spoof.hxx>
