/**
 * Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>
 * All rights reserved.
 * This is free software with ABSOLUTELY NO WARRANTY.
 *
 * You can redistribute it and/or modify it under the terms of 
 * the GNU General Public License version 2.
 */
static char rcsid[] = "$Id: bfd.c 330 2004-11-03 11:38:02Z ukai $";
#include <stdio.h>
#include <bfd.h>

int
main(int argc, char *argv[])
{
    bfd *abfd;
    bfd_init();
    abfd = bfd_openr(argv[1], NULL);
    if (abfd == NULL) {
	bfd_perror("bfd_openr");
	exit(1);
    }
    if (! bfd_check_format(abfd, bfd_object)) {
	bfd_perror("bfd_check_format");
    }

    printf("SYMBOL TABLE:\n");
    {
	long storage_needed;
	asymbol **symbol_table;
	long number_of_symbols;
	long i;
     
	storage_needed = bfd_get_symtab_upper_bound (abfd);

	printf("storage_need=%d\n", storage_needed);
     
	if (storage_needed < 0) {
	    bfd_perror("bfd_get_symtab_upper_bound");
	    exit(1);
	}
	if (storage_needed == 0) {
	    printf("no symbols\n");
	    exit(0);
	}
	symbol_table = (asymbol **)malloc (storage_needed);

	number_of_symbols = bfd_canonicalize_symtab (abfd, symbol_table);
	if (number_of_symbols < 0) {
	    bfd_perror("bfd_canonicalize_symtab");
	    exit(1);
	}
	for (i = 0; i < number_of_symbols; i++) {
	    asymbol *asym = symbol_table[i];
	    int symclass = bfd_decode_symclass(asym);
	    symbol_info syminfo;
	    bfd_symbol_info(asym, &syminfo);
	    bfd_print_symbol_vandf(abfd, stdout, asym);
	    printf(" 0x%x %s ", symclass, 
		   bfd_is_undefined_symclass(symclass) ? "?" : " ");
	    printf(" %s ", bfd_asymbol_name(asym));
	    printf("%p ", bfd_asymbol_value(asym));

	    // printf(" %d ", syminfo.value); /* asymbol_value */
	    // printf(" %d ", syminfo.type); /* symclass */
	    // printf(" %s ", syminfo.name); /* asymbol_name */
	    printf(" %d ", syminfo.stab_type);
	    printf(" %d ", syminfo.stab_other);
	    printf(" %d ", syminfo.stab_desc);
	    // printf(" %s ", syminfo.stab_name);
	    printf("\n");
	}
    }
    printf("DYNAMIC SYMBOL TABLE:\n");
    {
	long storage_needed;
	asymbol **symbol_table;
	long number_of_symbols;
	long i;
     
	storage_needed = bfd_get_dynamic_symtab_upper_bound (abfd);

	printf("storage_need=%d\n", storage_needed);
     
	if (storage_needed < 0) {
	    bfd_perror("bfd_get_symtab_upper_bound");
	    exit(1);
	}
	if (storage_needed == 0) {
	    printf("no symbols\n");
	    exit(0);
	}
	symbol_table = (asymbol **)malloc (storage_needed);

	number_of_symbols = bfd_canonicalize_dynamic_symtab (abfd, symbol_table);
	if (number_of_symbols < 0) {
	    bfd_perror("bfd_canonicalize_symtab");
	    exit(1);
	}
	for (i = 0; i < number_of_symbols; i++) {
	    asymbol *asym = symbol_table[i];
	    int symclass = bfd_decode_symclass(asym);
	    symbol_info syminfo;
	    bfd_symbol_info(asym, &syminfo);
	    bfd_print_symbol_vandf(abfd, stdout, asym);
	    printf(" 0x%x %s ", symclass, 
		   bfd_is_undefined_symclass(symclass) ? "?" : " ");
	    printf(" %s ", bfd_asymbol_name(asym));
	    printf("%p ", bfd_asymbol_value(asym));

	    // printf(" %d ", syminfo.value); /* asymbol_value */
	    // printf(" %d ", syminfo.type); /* symclass */
	    // printf(" %s ", syminfo.name); /* asymbol_name */
	    printf(" %d ", syminfo.stab_type);
	    printf(" %d ", syminfo.stab_other);
	    printf(" %d ", syminfo.stab_desc);
	    // printf(" %s ", syminfo.stab_name);
	    printf("\n");
	}
    }
    exit(0);
}
