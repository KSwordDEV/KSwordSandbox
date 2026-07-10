#include "Common/KernelString.h"

/*
 * Copies a bounded UTF-16 prefix for compact telemetry payloads.
 * Inputs : Destination is caller-owned fixed storage; DestinationChars is its
 *          WCHAR capacity; Source may be NULL; BytesCopied and Truncated are
 *          optional diagnostics for payload flags.
 * Logic  : avoids allocation, clamps to DestinationChars - 1 WCHARs, rounds to
 *          full WCHARs, writes a trailing NUL, and never reads beyond Source.
 * Return : TRUE when at least one WCHAR was copied; FALSE otherwise.
 */
BOOLEAN
KswCopyUnicodePrefix(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _Out_opt_ PULONG BytesCopied,
    _Out_opt_ PBOOLEAN Truncated
    )
{
    ULONG maxBytes;
    ULONG bytesToCopy;
    ULONG copiedChars;

    if (BytesCopied != NULL) {
        *BytesCopied = 0;
    }

    if (Truncated != NULL) {
        *Truncated = FALSE;
    }

    if (Destination == NULL || DestinationChars == 0) {
        return FALSE;
    }

    Destination[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return FALSE;
    }

    if (DestinationChars == 1) {
        if (Truncated != NULL) {
            *Truncated = TRUE;
        }
        return FALSE;
    }

    maxBytes = (DestinationChars - 1U) * (ULONG)sizeof(WCHAR);
    bytesToCopy = Source->Length;
    if (bytesToCopy > maxBytes) {
        bytesToCopy = maxBytes;
        if (Truncated != NULL) {
            *Truncated = TRUE;
        }
    }

    bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
    if (bytesToCopy == 0) {
        return FALSE;
    }

    RtlCopyMemory(Destination, Source->Buffer, bytesToCopy);
    copiedChars = bytesToCopy / (ULONG)sizeof(WCHAR);
    Destination[copiedChars] = L'\0';

    if (BytesCopied != NULL) {
        *BytesCopied = bytesToCopy;
    }

    return TRUE;
}
