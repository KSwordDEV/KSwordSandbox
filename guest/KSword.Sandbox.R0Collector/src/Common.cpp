#include "Common.h"

// Common.cpp intentionally owns shared collector translation-unit glue.
// The current common helpers are header-only constants/types, but keeping this
// module compiled preserves the multi-file project boundary for future shared
// formatting, time, and Win32 error helpers without growing main.cpp again.
