[WebUI](https://github.com/webui-dev/webui) but the bloat of webviews, window and browser management is removed.

The commit that is used as a base is probably [6c561ed](https://github.com/webui-dev/webui/commit/6c561ed739ce415e1e48ed17cb67c880aff1dc9d).
This was done a few months ago so it might be incorrect.

There is a patch applied in the `_webui_show_window` function :

```diff
else if (type == WEBUI_SHOW_FOLDER) {
	const char* folder_path = content;

	// Show a window using a local folder
	win->is_embedded_html = false;
	win->allow_index_fallback = true;

	// Set window URL
-	window_url = win->url;
+	size_t len = _webui_strlen(win->url);
+	window_url = (char*)_webui_malloc(len);
+	WEBUI_STR_COPY_DYN(window_url, len, win->url);
}
```

The build file uses [lbcs](https://github.com/x07x08/lua-lbcs). Read it or run `lua build.lua help` for more info.

The library must be in a path recognized by Lua. `LUA_PATH` can also be used. Works with both Lua and LuaJIT.

Requires [civetweb](https://github.com/civetweb/civetweb). Upstream is broken. Use a fork until it's fixed.

[The submodule version](https://github.com/x07x08/civetweb-smod) works as well.
