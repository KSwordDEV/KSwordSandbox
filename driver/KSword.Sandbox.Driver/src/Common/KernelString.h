#pragma once

#include "Driver.h"

/*
 * Copies a UNICODE_STRING prefix into a fixed WCHAR buffer.
 * Inputs : Destination points at a fixed WCHAR buffer, DestinationChars is the
 *          capacity in WCHARs, Source is optional kernel UTF-16 text, and
 *          BytesCopied receives the byte count excluding the trailing NUL.
 * Logic  : copies at most DestinationChars - 1 WCHARs, always terminates when
 *          capacity is non-zero, and reports whether truncation occurred.
 * Return : TRUE when source text was copied, FALSE for null or empty input.
 */
BOOLEAN
KswCopyUnicodePrefix(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _Out_opt_ PULONG BytesCopied,
    _Out_opt_ PBOOLEAN Truncated
    );

/*
 * Copies a bounded UTF-16 suffix, retaining the final path component when a
 * kernel callback path exceeds the compact payload capacity. This keeps image
 * and module names usable for behavior classification while preserving the
 * explicit truncation flag.
 */
BOOLEAN
KswCopyUnicodeSuffix(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _Out_opt_ PULONG BytesCopied,
    _Out_opt_ PBOOLEAN Truncated
    );
