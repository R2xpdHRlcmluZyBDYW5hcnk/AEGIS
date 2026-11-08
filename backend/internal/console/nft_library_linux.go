//go:build linux && cgo

package console

/*
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// Use the public libnftables ABI supplied by the system nftables package.
// Each command owns a context and its buffers; no third-party headers or code
// are bundled into this executable.
static void *aegis_nft_library;
static void *(*aegis_nft_new)(unsigned int);
static void (*aegis_nft_free)(void*);
static int (*aegis_nft_buffer_output)(void*);
static int (*aegis_nft_buffer_error)(void*);
static const char *(*aegis_nft_output)(void*);
static const char *(*aegis_nft_error)(void*);
static void (*aegis_nft_flags)(void*,unsigned int);
static int (*aegis_nft_run)(void*,const char*);
static int aegis_nft_available = -1;

static int aegis_nft_command(const char *command, int json, char **output, char **error) {
    *output = NULL; *error = NULL;
    if (aegis_nft_available < 0) {
        aegis_nft_available = 0;
        aegis_nft_library = dlopen("libnftables.so.1", RTLD_NOW | RTLD_LOCAL);
        if (aegis_nft_library) {
            aegis_nft_new = dlsym(aegis_nft_library,"nft_ctx_new");
            aegis_nft_free = dlsym(aegis_nft_library,"nft_ctx_free");
            aegis_nft_buffer_output = dlsym(aegis_nft_library,"nft_ctx_buffer_output");
            aegis_nft_buffer_error = dlsym(aegis_nft_library,"nft_ctx_buffer_error");
            aegis_nft_output = dlsym(aegis_nft_library,"nft_ctx_get_output_buffer");
            aegis_nft_error = dlsym(aegis_nft_library,"nft_ctx_get_error_buffer");
            aegis_nft_flags = dlsym(aegis_nft_library,"nft_ctx_output_set_flags");
            aegis_nft_run = dlsym(aegis_nft_library,"nft_run_cmd_from_buffer");
            aegis_nft_available = aegis_nft_new && aegis_nft_free && aegis_nft_buffer_output &&
                aegis_nft_buffer_error && aegis_nft_output && aegis_nft_error && aegis_nft_flags && aegis_nft_run;
        }
    }
    if (!aegis_nft_available) return -2;
    void *ctx = aegis_nft_new(0);
    if (!ctx) return -1;
    if (aegis_nft_buffer_output(ctx) || aegis_nft_buffer_error(ctx)) {
        aegis_nft_free(ctx); return -1;
    }
    if (json) aegis_nft_flags(ctx, 1u << 4); // NFT_CTX_OUTPUT_JSON public ABI
    int result = aegis_nft_run(ctx, command);
    const char *out = aegis_nft_output(ctx), *err = aegis_nft_error(ctx);
    *output = strdup(out ? out : ""); *error = strdup(err ? err : "");
    aegis_nft_free(ctx);
    return result;
}
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

var nftLibraryGate sync.Mutex

func nftLibraryCommand(command string, json bool) (string, error, bool) {
	nftLibraryGate.Lock()
	defer nftLibraryGate.Unlock()
	value := C.CString(command)
	defer C.free(unsafe.Pointer(value))
	var out, diagnostics *C.char
	var flags C.int
	if json {
		flags = 1
	}
	code := C.aegis_nft_command(value, flags, &out, &diagnostics)
	if code == -2 {
		return "", nil, false
	}
	defer C.free(unsafe.Pointer(out))
	defer C.free(unsafe.Pointer(diagnostics))
	result := C.GoString(out)
	if code != 0 {
		return C.GoString(diagnostics), errors.New("libnftables 操作失败"), true
	}
	return result, nil, true
}
