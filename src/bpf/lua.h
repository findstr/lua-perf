#ifndef _LUA_H
#define _LUA_H

#if defined(LUA_VERSION_5_5_0)
#include "lua_5_5_0.h"
#elif defined(LUA_VERSION_5_4_0)
#include "lua_5_4_0.h"
#elif defined(LUA_VERSION_5_3_6)
#include "lua_5_3_6.h"
#else
#error "Lua version not defined"
#endif

#endif