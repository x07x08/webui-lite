local lbcs = require("lbcs/lbcs")
local cCst = lbcs.C.Cst

local argMap = lbcs.makeArgMap(arg)

if (argMap["help"]) then
    print("Args:")

    print("")

    print(cCst.compilerArg .. " - C compiler")
    print(cCst.targetArg .. " - Defaults to \"Linux\"")

    print("")

    print("CW_OUT_PATH")
    print("CW_EXTRA_CFLAGS - Extra flags for civetweb")
    print("CW_EXTRA_LIBS - Extra libraries for civetweb")
    print("USE_STACK_SIZE - Thread stack size")
    print("CW_DYNAMIC_LIB")
    print("CW_STATIC_LIB")
    print("CIVETWEB_SRC_PATH")
    print("CIVETWEB_ONLY - Compile only civetweb")

    print("")

    print("WU_OUT_PATH")
    print("WU_EXTRA_CFLAGS - Extra flags for webui")
    print("WU_EXTRA_LIBS - Extra libraries for webui")
    print("WU_DYNAMIC_LIB")
    print("WU_STATIC_LIB")
    print("WEBUI_USE_TLS")

    return
end

local cwObj = lbcs.C.Types.BuildObj:init({}, {
    name = "civetweb",
    compiler = argMap[cCst.compilerArg],
    targetOS = argMap[cCst.targetArg],
    dynamic = (argMap["CW_DYNAMIC_LIB"] and (not argMap["CW_STATIC_LIB"])),
    outPath = argMap["CW_OUT_PATH"],
})

local cwStackSize = argMap["USE_STACK_SIZE"] or "102400"
local cwLibs = { "c", "pthread" }
local cwCFlags = "-Wall -Wextra -Wshadow -Wformat-security -Winit-self -Wmissing-prototypes"
cwCFlags = cwCFlags .. " " .. "-DUSE_STACK_SIZE=" .. cwStackSize

if (cwObj.targetOS == "Windows") then
    cwLibs = { "ws2_32" }
    cwCFlags = cwCFlags .. " " .. "-mwindows"
end

local wuObj = lbcs.C.Types.BuildObj:init({}, {
    name = "webui",
    compiler = argMap[cCst.compilerArg],
    targetOS = argMap[cCst.targetArg],
    dynamic = (argMap["WU_DYNAMIC_LIB"] and (not argMap["WU_STATIC_LIB"])),
    outPath = argMap["WU_OUT_PATH"],
})

local wuLibs = { "c", "pthread" }
local wuCFlags = "-DNDEBUG -DNO_CACHING -DNO_CGI -DUSE_WEBSOCKET -DUSE_IPV6"
local wuTLSCFlags = "-DNO_SSL"

if (cwObj.targetOS == "Windows") then
    wuLibs = { "ws2_32" }
    wuCFlags = wuCFlags .. " " .. "-mwindows"
end

local tlsLibs = { "ssl", "crypto" }

if (cwObj.targetOS == "Windows") then
    tlsLibs = { "ssl", "bcrypt" }
end

if (argMap["WEBUI_USE_TLS"]) then
    wuTLSCFlags = "-DWEBUI_TLS -DNO_SSL_DL -DOPENSSL_API_1_1"

    for _, value in ipairs(tlsLibs) do
        table.insert(wuLibs, value)
    end
end

if (not argMap["CIVETWEB_ONLY"]) then
    cwCFlags = table.concat({ cwCFlags, wuCFlags, wuTLSCFlags }, " ")

    if (argMap["WEBUI_USE_TLS"]) then
        for _, value in ipairs(tlsLibs) do
            table.insert(cwLibs, value)
        end
    end
end

cwObj.flags = { cwCFlags }
cwObj.libs = cwLibs
cwObj.incPaths = { argMap["EXTRA_INC_PATHS"] }

local cwSrcPath = argMap["CIVETWEB_SRC_PATH"] or ""
cwObj.inputs = { cwSrcPath .. "civetweb.c" }

if (wuObj.dynamic and (not cwObj.dynamic)) then
    table.insert(cwObj.flags, "-fPIC")
end

local ret, err = cwObj:compileLib(
    nil,
    argMap["CW_EXTRA_CFLAGS"],
    argMap["CW_EXTRA_LIBS"]
)

if (not ret) then
    print(err)
end

if (argMap["CIVETWEB_ONLY"]) then
    return
end

wuObj.flags = { wuCFlags }
wuObj.libs = wuLibs
wuObj.incPaths = { argMap["EXTRA_INC_PATHS"] }
wuObj.inputs = { "webui.c" }
wuObj.linkFiles = { cwObj:getLibOutPath() }

ret, err = wuObj:compileLib(
    nil,
    argMap["WU_EXTRA_CFLAGS"],
    argMap["WU_EXTRA_LIBS"]
)

if (not ret) then
    print(err)
end
