namespace SafeRuntime {
	size_t strlen(const char* str);
	int memcmp(const void* s1, const void* s2, size_t length);
	void memcpy(void* dest, void* src, size_t length);
	wchar_t towlower(wchar_t wc);
	int wstring_compare_i(const wchar_t* s1, const wchar_t* s2);
};