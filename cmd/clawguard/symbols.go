package main

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	symbolCacheMu sync.Mutex
	symbolCache   = map[string]symbolCacheEntry{} // path -> entry
)

type symbolCacheEntry struct {
	modTime int64
	size    int64
	offset  uint64
	ok      bool
}

var goTLSWriteCandidates = []string{
	"crypto/tls.(*Conn).Write",
	"crypto/tls.(*Conn).writeRecordLocked",
}

// resolveGoTLSWriteOffset finds the file offset for Go crypto/tls Write in exePath.
func resolveGoTLSWriteOffset(exePath string) (uint64, string, error) {
	fi, err := os.Stat(exePath)
	if err != nil {
		return 0, "", err
	}
	key := exePath
	symbolCacheMu.Lock()
	if e, ok := symbolCache[key]; ok && e.modTime == fi.ModTime().UnixNano() && e.size == fi.Size() {
		symbolCacheMu.Unlock()
		if !e.ok {
			return 0, "", fmt.Errorf("cached: no go tls write symbol in %s", exePath)
		}
		return e.offset, "cached", nil
	}
	symbolCacheMu.Unlock()

	offset, name, err := lookupGoTLSWrite(exePath)
	symbolCacheMu.Lock()
	symbolCache[key] = symbolCacheEntry{
		modTime: fi.ModTime().UnixNano(),
		size:    fi.Size(),
		offset:  offset,
		ok:      err == nil,
	}
	symbolCacheMu.Unlock()
	return offset, name, err
}

func lookupGoTLSWrite(exePath string) (uint64, string, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	// Prefer ELF symbol table when present (unstripped).
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	all := append(syms, dyn...)
	for _, cand := range goTLSWriteCandidates {
		for _, s := range all {
			if s.Name == cand && s.Value != 0 {
				off, err := symFileOffset(f, s.Value)
				if err != nil {
					continue
				}
				return off, cand, nil
			}
		}
	}

	// Fall back to pclntab / gosym (works on stripped Go binaries).
	off, name, err := lookupViaGosym(f, exePath)
	if err == nil {
		return off, name, nil
	}
	return 0, "", fmt.Errorf("go tls write symbol not found in %s: %w", exePath, err)
}

func lookupViaGosym(f *elf.File, exePath string) (uint64, string, error) {
	var (
		pclntab []byte
		symtab  []byte
		textStart uint64
	)
	if sec := f.Section(".gopclntab"); sec != nil {
		var err error
		pclntab, err = sec.Data()
		if err != nil {
			return 0, "", err
		}
	}
	if sec := f.Section(".gosymtab"); sec != nil {
		var err error
		symtab, err = sec.Data()
		if err != nil {
			return 0, "", err
		}
	}
	if pclntab == nil {
		// Go 1.16+ often embeds pclntab in runtime section; try buildinfo path via LineTable from raw.
		return 0, "", fmt.Errorf("no .gopclntab")
	}
	if text := f.Section(".text"); text != nil {
		textStart = text.Addr
	}
	lt := gosym.NewLineTable(pclntab, textStart)
	table, err := gosym.NewTable(symtab, lt)
	if err != nil {
		return 0, "", err
	}
	for _, cand := range goTLSWriteCandidates {
		for _, fn := range table.Funcs {
			if fn.Name == cand {
				off, err := symFileOffset(f, fn.Entry)
				if err != nil {
					continue
				}
				return off, cand, nil
			}
		}
		// Substring match for unusual mangling
		for _, fn := range table.Funcs {
			if strings.Contains(fn.Name, "crypto/tls.(*Conn).Write") && !strings.Contains(fn.Name, "writeRecord") {
				off, err := symFileOffset(f, fn.Entry)
				if err != nil {
					continue
				}
				return off, fn.Name, nil
			}
		}
	}
	_ = exePath
	return 0, "", fmt.Errorf("gosym: candidates not found")
}

func symFileOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if addr >= prog.Vaddr && addr < prog.Vaddr+prog.Memsz {
			return addr - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("address %#x not in executable segment", addr)
}

func isGoBinary(path string) bool {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return false
	}
	return bi != nil && bi.GoVersion != ""
}
