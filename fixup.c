/**
 * Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>
 * All rights reserved.
 * This is free software with ABSOLUTELY NO WARRANTY.
 *
 * You can redistribute it and/or modify it under the terms of 
 * the GNU General Public License version 2.
 */

#include <stdio.h>
#include <string.h>
#include <bfd.h>
#include <elf.h>
#include <link.h>

/* glibc/elf/dl-runtime.c */
#if (!defined ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) \
    || ELF_MACHINE_NO_REL
# define PLTREL  ElfW(Rela)
#else
# define PLTREL  ElfW(Rel)
#endif

/* glibc/sysdeps/generic/ldsodefs.h */
#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)

struct symaddr {
    struct symaddr *next;
    char *name;
    int addr;
} *symaddrs;

int
lookup_symaddr(char *name) 
{
    struct symaddr *sa;
    for (sa = symaddrs; sa != NULL && sa->name != NULL; sa = sa->next) {
	if (strcmp(name, sa->name) == 0) {
	    return sa->addr;
	}
    }
    return 0;
}

void
add_symaddr(const char *name, int addr)
{
    struct symaddr *sa;

    if (*name == '\0')
	return;

    sa = (struct symaddr *)malloc(sizeof(struct symaddr));
    memset(sa, 0, sizeof(struct symaddr));
    sa->name = strdup(name);
    sa->addr = addr;
    sa->next = symaddrs;
    symaddrs = sa;
    return;
}

int
bfd_read_symbols(bfd *abfd, int offset)
{
    long storage_needed;
    asymbol **symbol_table = NULL;
    long number_of_symbols;
    long i;
    int ret = 0;
     
    /* symbol table */
    fprintf(stderr, "SYMBOL TABLE:\n");
    storage_needed = bfd_get_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
	bfd_perror("bfd_get_symtab_upper_bound");
	ret = -1;
	goto dynsym;
    }
    if (storage_needed == 0) {
	fprintf(stderr, "no symbols\n");
	goto dynsym;
    }
    symbol_table = (asymbol **)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_symtab (abfd, symbol_table);
    if (number_of_symbols < 0) {
	bfd_perror("bfd_canonicalize_symtab");
	ret = -1;
	goto dynsym;
    }
    for (i = 0; i < number_of_symbols; i++) {
	asymbol *asym = symbol_table[i];
	const char *sym_name = bfd_asymbol_name(asym);
	int symclass = bfd_decode_symclass(asym);
	int sym_value = bfd_asymbol_value(asym) + offset;
	if (*sym_name == '\0')
	    continue;
	if (bfd_is_undefined_symclass(symclass))
	    continue;
	fprintf(stderr, " %s=", sym_name);
	fprintf(stderr, "%p", sym_value);
	add_symaddr(sym_name, sym_value);
	fprintf(stderr, "\n");
    }
dynsym:
    if (symbol_table)
	free(symbol_table);
    symbol_table = NULL;

    fprintf(stderr, "DYNAMIC SYMBOL TABLE:\n");
    storage_needed = bfd_get_dynamic_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
	bfd_perror("bfd_get_dynamic_symtab_upper_bound");
	ret = -1;
	goto out;
    }
    if (storage_needed == 0) {
	fprintf(stderr, "no symbols\n");
	goto out;
    }
    symbol_table = (asymbol **)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_dynamic_symtab (abfd, symbol_table);
    if (number_of_symbols < 0) {
	bfd_perror("bfd_canonicalize_symtab");
	ret = -1;
	goto dynsym;
    }
    for (i = 0; i < number_of_symbols; i++) {
	asymbol *asym = symbol_table[i];
	const char *sym_name = bfd_asymbol_name(asym);
	int symclass = bfd_decode_symclass(asym);
	int sym_value = bfd_asymbol_value(asym) + offset;
	if (*sym_name == '\0')
	    continue;
	if (bfd_is_undefined_symclass(symclass))
	    continue;
	fprintf(stderr, " %s=", sym_name);
	fprintf(stderr, "%p", sym_value);
	add_symaddr(sym_name, sym_value);
	fprintf(stderr, "\n");
    }
out:
    if (symbol_table)
	free(symbol_table);
    return ret;
}

void *
bfd_load_section(bfd *abfd, char *sect_name, int *sz)
{
    asection *sect;
    int size;
    char *buf;
    sect = bfd_get_section_by_name(abfd, sect_name);
    if (sect == NULL) {
	return NULL;
    }
    size = bfd_get_section_size_before_reloc(sect);
    buf = (char *)malloc(size);
    bfd_get_section_contents(abfd, sect, buf, 0, size);
    if (sz)
	*sz = size;
    return buf;
}

void
fixup(bfd *abfd, ElfW(Sym) *symtab, char *strtab, PLTREL *reloc, 
      char *outbuf, int outsize)
{
    ElfW(Sym) *sym;
    int rel_addr;
    int addr;
    char *sym_name;

    sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    rel_addr = reloc->r_offset;
    sym_name = &strtab[sym->st_name];
    fprintf(stderr, "%s @ %d 0x%x ", sym_name, rel_addr, rel_addr);
    addr = lookup_symaddr(sym_name);
    if (addr) {
	fprintf(stderr, "= %p", addr);
	*(int *)(outbuf + rel_addr) = addr;
    } else {
	fprintf(stderr, "=*UND*");
    }
    fprintf(stderr, "\n");
    return;
}

int
fixups(bfd *abfd, char *outbuf, int outsize)
{
    ElfW(Sym) *symtab;
    char *strtab;
    PLTREL *reloc, *reloc_end;
    int reloc_size;


    symtab = (ElfW(Sym)*)bfd_load_section(abfd, ".dynsym", NULL);
    if (symtab == NULL) {
	fprintf(stderr, "load error .dynsym\n");
	exit(1);
    }
    strtab = (char *)bfd_load_section(abfd, ".dynstr", NULL);
    if (strtab == NULL) {
	fprintf(stderr, "load error .dynstr\n");
	exit(1);
    }
    reloc = (PLTREL *)bfd_load_section(abfd, ".rel.dyn", &reloc_size);
    if (reloc == NULL) {
	goto next;
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    fprintf(stderr, "reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc = (PLTREL*)((char *)reloc + 8)) {
	fixup(abfd, symtab, strtab, reloc, outbuf, outsize);
    }

next:
    reloc = (PLTREL *)bfd_load_section(abfd, ".rel.plt", &reloc_size);
    if (reloc == NULL) {
	fprintf(stderr, "load error .rel.plt\n");
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    fprintf(stderr, "reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc = (PLTREL*)((char *)reloc + 8)) {
	fixup(abfd, symtab, strtab, reloc, outbuf, outsize);
    }
}

void
bfd_map_section_alloc_size(bfd *abfd, asection *sect, void *obj)
{
    int *outsizep = (int *)obj;
    int vma = bfd_get_section_vma(abfd, sect);
    int size = bfd_get_section_size_before_reloc(sect);
    int flags = bfd_get_section_flags(abfd, sect);
    if ((flags & (SEC_ALLOC|SEC_LOAD)) != 0) {
	if ((vma + size) > *outsizep)
	    *outsizep = align_power(vma + size, 
				    bfd_get_section_alignment(abfd, sect));
    }
}

void
bfd_map_section_buf(bfd *abfd, asection *sect, void *obj)
{
    char *outbuf = (char *)obj;
    int vma = bfd_get_section_vma(abfd, sect);
    int size = bfd_get_section_size_before_reloc(sect);
    int flags = bfd_get_section_flags(abfd, sect);
    if ((flags & (SEC_ALLOC|SEC_LOAD)) != 0) {
	fprintf(stderr, "section %s @ %p size %d flags 0x%0x\n", 
		bfd_get_section_name(abfd, sect), vma, size, flags);
	bfd_get_section_contents(abfd, sect, outbuf + vma, 0, size);
    }
}

int
main(int argc, char *argv[])
{
    bfd *abfd;
    char *outbuf;
    int outsize;
    FILE *fp;
    char line[4096];

    if (argc < 3) {
	fprintf(stderr, "usage: %s in out\n");
	exit(1);
    }

    bfd_init();
    while (fgets(line, sizeof(line), stdin) != NULL) {
	char *fn = line;
	int offset = 0;
	line[strlen(line)-1] = '\0'; /* chomp */
	char *p = strchr(line, ' ');
	if (p) {
	    *p = '\0';
	    offset = strtol(p+1, NULL, 0);
	}
	abfd = bfd_openr(fn, NULL);
	if (abfd == NULL) {
	    bfd_perror("bfd_openr");
	    exit(1);
	}
	bfd_check_format(abfd, bfd_object);
	fprintf(stderr, "read symbols %s offset %p\n", fn, offset);
	bfd_read_symbols(abfd, offset);
	bfd_close(abfd);
    }
    
    abfd = bfd_openr(argv[1], NULL);
    if (abfd == NULL) {
	bfd_perror("bfd_openr");
	exit(1);
    }
    bfd_check_format(abfd, bfd_object);
    outsize = 0;
    bfd_map_over_sections(abfd, bfd_map_section_alloc_size, &outsize);
    outbuf = (char *)malloc(outsize);
    if (outbuf == NULL) {
	perror("malloc");
	exit(1);
    }
    memset(outbuf, 0, outsize);
    bfd_map_over_sections(abfd, bfd_map_section_buf, outbuf); /* XXX size */

    fixups(abfd, outbuf, outsize);

    bfd_read_symbols(abfd, 0); /* XXX */
    bfd_close(abfd);

    fp = fopen(argv[2], "w");
    fwrite(outbuf, outsize, 1, fp);
    fclose(fp);
    exit(0);
}
