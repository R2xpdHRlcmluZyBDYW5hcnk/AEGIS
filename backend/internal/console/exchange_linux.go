//go:build linux && cgo

package console

/*
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
extern int sqlite3_complete(const char*);
*/
import "C"
import "unsafe"

func sqliteStatementComplete(statement []byte) bool {
	value := C.CString(string(statement))
	defer C.free(unsafe.Pointer(value))
	return C.sqlite3_complete(value) != 0
}

func exchangeFiles(first, second string) error {
	a, b := C.CString(first), C.CString(second)
	defer C.free(unsafe.Pointer(a))
	defer C.free(unsafe.Pointer(b))
	result, err := C.renameat2(C.AT_FDCWD, a, C.AT_FDCWD, b, 2)
	if result != 0 {
		return err
	}
	return nil
}
