#pragma once

/* Shim for PS4 Payload SDK builds.
 *
 * PS4_PAYLOAD_SDK does not ship an orbis/libkernel.h header, but it does
 * export sceKernelDebugOutText from its libkernel.so stub. libLog's header
 * and source both `#include <orbis/libkernel.h>` when __LIBLOG_PC__ is not
 * defined, so we provide this minimal declaration.
 */

#ifdef __cplusplus
extern "C" {
#endif

int sceKernelDebugOutText(int dbgChannel, const char *text);

#ifdef __cplusplus
}
#endif
