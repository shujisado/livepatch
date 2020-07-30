/**
 * Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>
 * All rights reserved.
 * This is free software with ABSOLUTELY NO WARRANTY.
 *
 * You can redistribute it and/or modify it under the terms of 
 * the GNU General Public License version 2.
 */
static char rcsid[] = "$Id: livepatch.c 351 2004-11-08 16:05:26Z ukai $";
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/user.h>
#include <bfd.h>
#include <elf.h>
#include <link.h>
#define _GNU_SOURCE
#include <getopt.h>

/*****************/

int opt_debug;
int opt_verbose;
int opt_quiet;

#define DEBUG(fmt,...)	do {if (opt_debug) printf(fmt, __VA_ARGS__);} while (0)
#define INFO(fmt,...) do {if (opt_verbose) printf(fmt, __VA_ARGS__);} while (0)
#define NOTICE(fmt,...) do {if (!opt_quiet) printf(fmt, __VA_ARGS__);} while (0)
#define ERROR(fmt,...) do { fprintf(stderr, fmt, __VA_ARGS__);} while (0)


/*****************/
#if defined(linux) && defined(i386)
/* sysdeps/i386/dl-machine.h */
/* The i386 never uses Elf32_Rela relocations for the dynamic linker.
 *    Prelinked libraries may use Elf32_Rela though.  */
#define ELF_MACHINE_PLT_REL 1
#else
#error Unsupported platform
#endif

/* glibc/elf/dl-runtime.c */
#if (!defined ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) \
    || ELF_MACHINE_NO_REL
# define PLTREL  ElfW(Rela)
#else
# define PLTREL  ElfW(Rel)
#endif

/* glibc/sysdeps/generic/ldsodefs.h */
#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)

/* FIXME: too slow lookup, use hashtable or so */
struct symaddr {
    struct symaddr *next;
    char *name;
    int addr;
} *symaddrs;

int
lookup_symaddr(char *name, struct symaddr *symaddr0) 
{
    struct symaddr *sa;
    for (sa = symaddr0; sa != NULL && sa->name != NULL; sa = sa->next) {
	if (strcmp(name, sa->name) == 0) {
	    return sa->addr;
	}
    }
    DEBUG("[symaddr %s not found]", name);
    return 0;
}

void
add_symaddr(const char *name, int addr, struct symaddr **symaddrp)
{
    struct symaddr *sa;

    if (*name == '\0')
	return;

    sa = (struct symaddr *)malloc(sizeof(struct symaddr));
    memset(sa, 0, sizeof(struct symaddr));
    sa->name = strdup(name);
    sa->addr = addr;
    sa->next = *symaddrp;
    *symaddrp = sa;
    return;
}

int
bfd_read_symbols(bfd *abfd, int offset, struct symaddr **symaddrp)
{
    long storage_needed;
    asymbol **symbol_table = NULL;
    long number_of_symbols;
    long i;
    int ret = 0;
     
    /* symbol table */
    DEBUG("%s\n","SYMBOL TABLE:");
    storage_needed = bfd_get_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
	bfd_perror("bfd_get_symtab_upper_bound");
	ret = -1;
	goto dynsym;
    }
    if (storage_needed == 0) {
	DEBUG("%s\n", "no symbols");
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
	DEBUG(" %s=%p\n", sym_name, (void *)sym_value);
	add_symaddr(sym_name, sym_value, symaddrp);
    }
dynsym:
    if (symbol_table)
	free(symbol_table);
    symbol_table = NULL;

    DEBUG("%s\n", "DYNAMIC SYMBOL TABLE:");
    storage_needed = bfd_get_dynamic_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
	bfd_perror("bfd_get_dynamic_symtab_upper_bound");
	ret = -1;
	goto out;
    }
    if (storage_needed == 0) {
	DEBUG("%s\n", "no symbols");
	goto out;
    }
    symbol_table = (asymbol **)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_dynamic_symtab (abfd, symbol_table);
    if (number_of_symbols < 0) {
	bfd_perror("bfd_canonicalize_symtab");
	ret = -1;
	goto out;
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
	DEBUG(" %s=%p\n", sym_name, (void *)sym_value);
	add_symaddr(sym_name, sym_value, symaddrp);
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
      struct symaddr *symaddr0, char *outbuf, int outsize)
{
    ElfW(Sym) *sym;
    int rel_addr;
    int addr;
    char *sym_name;

    sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    rel_addr = reloc->r_offset;
    sym_name = &strtab[sym->st_name];
    INFO("%s @ %d 0x%x ", sym_name, rel_addr, rel_addr);
    addr = lookup_symaddr(sym_name, symaddr0);
    if (addr) {
	*(int *)(outbuf + rel_addr) = addr;
	INFO("= %p\n", (void *)addr);
    } else {
	INFO("= %s\n", "*UND*");
    }
    return;
}

int
fixups(bfd *abfd, struct symaddr *symaddr0, char *outbuf, int outsize)
{
    ElfW(Sym) *symtab;
    char *strtab;
    PLTREL *reloc, *reloc_end;
    int reloc_size;


    DEBUG("%s...\n", "fixups");
    symtab = (ElfW(Sym)*)bfd_load_section(abfd, ".dynsym", NULL);
    if (symtab == NULL) {
	ERROR("load error %s\n", ".dynsym");
	return -1;
    }
    strtab = (char *)bfd_load_section(abfd, ".dynstr", NULL);
    if (strtab == NULL) {
	ERROR("load error %s\n", ".dynstr");
	return -1;
    }
    reloc = (PLTREL *)bfd_load_section(abfd, ".rel.dyn", &reloc_size);
    if (reloc == NULL) {
	ERROR("load error? %s\n", ".rel.dyn");
	goto rel_plt;
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    DEBUG(".rel.dyn reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc++) {
	fixup(abfd, symtab, strtab, reloc, symaddr0, outbuf, outsize);
    }

rel_plt:
    reloc = (PLTREL *)bfd_load_section(abfd, ".rel.plt", &reloc_size);
    if (reloc == NULL) {
	ERROR("load error %s\n", ".rel.plt");
	return -1;
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    DEBUG(".rel.plt reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc++) {
	fixup(abfd, symtab, strtab, reloc, symaddr0, outbuf, outsize);
    }
    return 0;
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
	DEBUG("section %s @ %p size %d flags 0x%0x\n", 
	      bfd_get_section_name(abfd, sect), (void *)vma, size, flags);
	bfd_get_section_contents(abfd, sect, outbuf + vma, 0, size);
    }
}

int
target_symbol_initialize(pid_t pid, char *filename)
{
    bfd *abfd;
    char buf[4096];
    FILE *fp;

    DEBUG("target symbol initialize: pid %d filename %s\n",
	  pid, filename);
    snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
    DEBUG("proc map %s\n", buf);
    fp = fopen(buf, "r");
    if (fp == NULL) {
	perror("open /proc/$$/maps");
	return -1;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
	/* linux/fs/proc/task_mmu.c */
	int vm_start, vm_end, pgoff, major, minor, ino;
	char flags[5], mfilename[4096];
	if (sscanf(buf, "%x-%x %4s %x %d:%d %d %s",
		   &vm_start, &vm_end, flags, &pgoff, &major, &minor, &ino, 
		   mfilename) < 7) {
	    ERROR("E: invalid format in /proc/$$/maps? %s", buf);
	    continue;
	}
	DEBUG("0x%x-0x%x %s 0x%x %s\n",
	      vm_start, vm_end, flags, pgoff, mfilename);
	if (flags[0] == 'r' && flags[2] == 'x' 
	    && pgoff == 0 && *mfilename != '\0') {
	    DEBUG("file %s @ %p\n", mfilename, (void *)vm_start);
	    abfd = bfd_openr(mfilename, NULL);
	    if (abfd == NULL) {
		bfd_perror("bfd_openr");
		continue;
	    }
	    bfd_check_format(abfd, bfd_object);
	    bfd_read_symbols(abfd, vm_start, &symaddrs);
	    bfd_close(abfd);
	}
    }
    DEBUG("target file %s\n", filename);
    abfd = bfd_openr(filename, NULL);
    if (abfd == NULL) {
	bfd_perror("bfd_openr");
	return -1;
    }
    bfd_check_format(abfd, bfd_object);
    bfd_read_symbols(abfd, 0, &symaddrs);
    bfd_close(abfd);
    return 0;
}

/*****************/
int
push_stack(pid_t pid, struct user_regs_struct *regs, long v)
{
    regs->esp -= 4;
    if (ptrace(PTRACE_POKEDATA, pid, regs->esp, v) < 0) {
	perror("ptrace poke stack");
	return -1;
    }
    return 0;
}

long
target_alloc(pid_t pid, size_t siz)
{
    struct user_regs_struct regs, oregs;
    char code[] = {0xcd, 0x80, 0xcc, 0x00}; /* int $0x80, int3,  */
    long lv;
    long raddr;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &oregs) < 0) {
	perror("ptrace getregs");
	return 0;
    }

    regs = oregs;
    DEBUG("%%esp = %p\n", (void *)regs.esp);
    regs.esp -= sizeof(int);
    memcpy(&lv, code, 4);
    if (ptrace(PTRACE_POKEDATA, pid, regs.esp, lv) < 0) {
	perror("ptrace poke code");
	return 0;
    }
    regs.eip = regs.esp;  /* int $0x80 */
    raddr = regs.esp + 2; /* int3 */
    /* 
     * mmap(NULL, siz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
     */

    push_stack(pid, &regs, 0); /* arg 6 (offset) */
    push_stack(pid, &regs, -1);
    push_stack(pid, &regs, MAP_PRIVATE|MAP_ANONYMOUS);
    push_stack(pid, &regs, PROT_READ|PROT_WRITE);
    push_stack(pid, &regs, siz);
    push_stack(pid, &regs, 0);
    push_stack(pid, &regs, raddr);
    regs.ebx = regs.esp + 4; /* arg 1 (ptr to args) */
    regs.eax = SYS_mmap; /* system call number */
    /**
     * stack will be:
     *     %esp: return address
     *  4(%esp): arg 1 <- %ebx : pointer to args
     *  8(%esp): arg 2
     * 12(%esp): arg 3
     * 16(%esp): arg 4
     * 20(%esp): arg 5
     * 24(%esp): arg 6
     * 28(%esp): int $0x80	<- %eip jump address
     * 30(%esp): int3		<- return address
     * 31(%esp): --
     * 32(%esp): original esp
     * 
     * glibc/sysdeps/unix/sysv/linux/i386/mmap.S
     */
    DEBUG("target_alloc %s\n", "set regs");
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
	perror("ptrace set regs");
	return 0;
    }
    DEBUG("target_allloc %s\n", "mmap call");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
	perror("ptrace cont");
	return 0;
    }
    wait(NULL);
    DEBUG("target_alloc %s\n", "mmap done");
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
	perror("ptrace get regs of mmap");
	return 0;
    }
    lv = regs.eax; /* return value */
    if ((void *)lv == MAP_FAILED) {
	DEBUG("target_alloc failed %p\n", (void *)0);
	return 0;
    }
    INFO("allocated = %p %d bytes\n", (void*)lv, siz);

    /* restore old regs */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &oregs) < 0) {
	perror("ptrace restore regs");
	return 0;
    }
    return lv;
}

int
set_data(pid_t pid, int addr, void *val, int vlen)
{
    int i;
    int addr0 = addr & ~3;
    int len = (((addr + vlen) - addr0) + 3)/4;
    int *lv = malloc(len * sizeof(int));

    DEBUG("peek: %d", len);
    for (i = 0; i < len; i++) {
	if (i % 4 == 0) {
	    DEBUG("\n %p  ", (void *)(addr0 + i * sizeof(int)));
	}
	lv[i] = ptrace(PTRACE_PEEKDATA, pid, 
		       addr0 + i * sizeof(int), NULL);
	if (lv[i] == -1 && errno != 0) {
	    perror("ptrace peek");
	    return -1;
	}
	DEBUG("%08x ", lv[i]);
    }
    memcpy((char *)lv + (addr - addr0), val, vlen);
    DEBUG("\npoke: %d", len);
    for (i = 0; i < len; i++) {
	if (i % 4 == 0) {
	    DEBUG("\n %p  ", (void *)(addr0 + i * sizeof(int)));
	}
	if (ptrace(PTRACE_POKEDATA, pid,
		   addr0 + i * sizeof(int), lv[i]) < 0) {
	    perror("ptrace poke");
	    return -1;
	}
	DEBUG("%08x ", lv[i]);
    }
    DEBUG("%s", "\n"); /* XXX */
    return 0;
}

struct memvar {
    struct memvar *next;
    char *name;
    long addr;
    struct symaddr *syms;
} *memvartab;

long
lookup_memvar(char *name)
{
    struct memvar *mv;
    int namelen = strlen(name);
    char *sym = strchr(name, ':');
    if (sym) {
	namelen = sym - name;
	sym += 1;
    }
    // printf("lookup_memvar %s sym %s", name, sym);
    for (mv = memvartab; mv != NULL && mv->name != NULL; mv = mv->next) {
	if (strncmp(name, mv->name, namelen) == 0) {
	    if (sym != NULL) {
		if (isdigit(*sym)) {
		    int offset = strtol(sym, NULL, 0);
		    return mv->addr + offset;
		} else if (mv->syms != NULL) {
		    return lookup_symaddr(sym, mv->syms);
		}
	    } else {
		return mv->addr;
	    }
	}
    }
    ERROR("memvar %s not found\n", name);
    return 0;
}

void
set_memvar(char *name, long addr, struct symaddr *syms)
{
    struct memvar *mv = (struct memvar *)malloc(sizeof(struct memvar));
    memset(mv, 0, sizeof(struct memvar));
    mv->name = strdup(name);
    mv->addr = addr;
    mv->syms = syms;
    mv->next = memvartab;
    memvartab = mv;
    DEBUG("memvar %s set to %p syms:%p\n", name, (void *)addr, syms);
    return;
}

int
lookup_addr(char *addrinfo) {
    int addr = 0;
    DEBUG("lookup_addr %s => ", addrinfo);
    if (*addrinfo == '$') {
	addr = lookup_memvar(addrinfo+1);
    } else if (isdigit(*addrinfo)) {
	addr = strtol(addrinfo, NULL, 0);
    } else {
	addr = lookup_symaddr(addrinfo, symaddrs);
    }
    DEBUG("%p\n", (void *)addr);
    return addr;
}

void
parse_data(char *type, char *p, void **vptr, int *vlenp)
{
    DEBUG("data type=%s\n", type);
    if (strcmp(type, "int") == 0) {
	*vptr = (int*)malloc(sizeof(int));
	*vlenp = sizeof(int);
	*(int *)*vptr = strtol(p, NULL, 0);
    } else if (strcmp(type, "str") == 0) {
	*vlenp = strlen(p);
	*vptr = malloc(*vlenp);
	memcpy(*vptr, p, *vlenp);
    } else if (strcmp(type, "addr") == 0) {
	*vptr = (int*)malloc(sizeof(int));
	*vlenp = sizeof(int);
	*(int *)*vptr = lookup_addr(p);
    } else if (strcmp(type, "hex") == 0) {
	int i;
	int v;
	*vlenp = (strlen(p) + 1)/2;
	*vptr = malloc(*vlenp);
	for (i = 0; i < *vlenp; i++) {
	    sscanf(p+i*2, "%02x", &v);
	    ((char *)*vptr)[i] = v;
	}
    }
    return;
}

char *
format_data(char *type, char *p, void *vptr, int vlen)
{
    static char databuf[4096]; /* XXX */

    if (strcmp(type, "int") == 0) {
	snprintf(databuf, sizeof(databuf)-1, "%d (%s)", *(int*)vptr, p);
    } else if (strcmp(type, "str") == 0) {
	snprintf(databuf, sizeof(databuf)-1, "\"%s\" [%d]", 
		 (char *)vptr, vlen);
    } else if (strcmp(type, "addr") == 0) {
	snprintf(databuf, sizeof(databuf)-1, "@%p (%s)", 
		 (void *)(*(int *)vptr), p);
    } else if (strcmp(type, "hex") == 0) {
	snprintf(databuf, sizeof(databuf)-1, "hex [%d]", vlen);
    }
    return databuf;
}

void
usage(char *prog)
{
    printf("Usage: %s [option] <pid> <target-binary>\n"
	   "  apply binary patches to running process.\n"
	   "  read stdin for patch instructions.\n"
	   "  --help	help message.\n"
	   "  --quiet	quiet mode.\n"
	   "  --verbose	verbose mode.\n"
	   "  --debug	turn on debug message.\n"
	   "\n"
	   "%s\n"
           "Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>\n"
	   "All rights reserved.\n"
	   "This is free software with ABSOLUTELY NO WARRANTY.\n", 
	   prog, rcsid);
    return;
}

void
help(char *prog)
{
    usage(prog);
    printf("\n");
    printf("patch instructions:\n"
	   "[instruction line]\n"
	   "set <addr> <type> <value>     # set value to address\n"
	   "new <memname> <size>          # allocate new memory space\n"
	   "load <memname> <filename>     # load file in memory space\n"
	   "dl <memname> <filename>       # load & symbol fixups.\n"
	   "jmp <addr1> <addr2>           # set jmp to addr2 at addr1.\n"
	   "\n"
	   "[parameter]\n"
	   "addr := <integer> | $<memname> | $<memname>:<symbol> | <symbol>\n"
	   "type := int | str | hex | addr\n"
	   "  int - integer parsed by strtol(i,NULL,0); size = 4\n"
	   "  str - string until '\\n'\n"
	   "  hex - ([0-9A-Fa-f]{2})*\n"
	   "  addr - addr above\n"
	   "\n");
    return;
}

int
main(int argc, char *argv[])
{
    pid_t target_pid;
    char *target_filename;
    char buf[4096];
    static struct option long_opts[] = {
	{"debug", no_argument, &opt_debug, 1},
	{"verbose", no_argument, &opt_verbose, 1},
	{"quiet", no_argument, &opt_quiet, 1},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
    };
    int opt_index;

    while (1) {
	int c;
	c = getopt_long(argc, argv, "dvqh", long_opts, &opt_index);
	if (c == -1)
	    break;
	switch (c) {
	case 0: /* long options */; break;
	case 'd': opt_debug = 1; break;
	case 'v': opt_verbose = 1; break;
	case 'q': opt_quiet = 1; break;
	case 'h': help(argv[0]); exit(0);
	case '?': /* FALLTHROUGH */
	default:
	    usage(argv[0]); exit(1);
	}
    }
    if (opt_quiet) {
	opt_debug = opt_verbose = 0;
    }

    if (argc < optind + 2) {
	usage(argv[0]);
	exit(1);
    }
    bfd_init();
    target_pid = atoi(argv[optind]);
    target_filename = argv[optind+1];
    target_symbol_initialize(target_pid, target_filename);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
	perror("ptrace attach");
	exit(1);
    }
    DEBUG("attached %d\n", target_pid);
    wait(NULL);

    /**
     * see help()
     */
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
	DEBUG("I: %s", buf);
	if (strncmp(buf, "set ", 4) == 0) {
	    char addrinfo[4096];
	    char type[4096];
	    char val[4096];
	    int addr;
	    void *v;
	    int vlen;

	    if (sscanf(buf, "set %s %s %s\n", addrinfo, type, val) != 3) {
		ERROR("E: invalid set line: %s", buf);
		continue;
	    }
	    addr = lookup_addr(addrinfo);
	    parse_data(type, val, &v, &vlen);

	    INFO("set pid=%d addr=%p value=%s\n", target_pid, 
		 (void *)addr, format_data(type, val, v, vlen));
	    if (set_data(target_pid, addr, v, vlen) < 0) {
		ERROR("E: set %p %s %s failed\n", (void *)addr, type, val);
		continue;
	    }
	    NOTICE("set %p %s %s\n", (void *)addr, type, val);

	} else if (strncmp(buf, "new ", 4) == 0) {
	    char memname[4096];
	    char sizeinfo[4096];
	    int siz;
	    int addr;

	    if (sscanf(buf, "new %s %s\n", memname, sizeinfo) != 2) {
		ERROR("E: invalid new line: %s", buf);
		continue;
	    }
	    siz = strtol(sizeinfo, NULL, 0);
	    INFO("new pid=%d memvar=%s size=%d\n", target_pid, 
		 memname, siz);
	    addr = target_alloc(target_pid, siz);
	    if (addr == 0) {
		ERROR("E: target_alloc failed. pid=%d size=%d\n", 
		      target_pid, siz);
		continue;
	    }
	    set_memvar(memname, addr, NULL);
	    NOTICE("new %s @ %p [%d]\n", memname, (void *)addr, siz);

	} else if (strncmp(buf, "load ", 5) == 0) {
	    char memname[4096];
	    char filename[4096];
	    struct stat st;
	    char *p;
	    long addr;
	    FILE *fp;

	    if (sscanf(buf, "load %s %s\n", memname, filename) != 2) {
		ERROR("E: invalid load line: %s", buf);
		continue;
	    }
	    if (stat(filename, &st) < 0) {
		perror("stat");
		continue;
	    }
	    INFO("load pid=%d memvar=%s filename=%s size=%ld\n", 
		 target_pid, memname, filename, st.st_size);
	    /*
	     * TODO: mmap on file in target?
	     */
	    p = malloc(st.st_size);
	    if (p == NULL) {
		ERROR("E: malloc failed. size=%ld\n", st.st_size);
		continue;
	    }
	    fp = fopen(filename, "r");
	    if (fp == NULL) {
		ERROR("E: fopen %s error\n", filename);
		continue;
	    }
	    if (fread(p, st.st_size, 1, fp) == 0) {
		ERROR("E: fread error. %ld\n", st.st_size);
		continue;
	    }
	    fclose(fp);

	    addr = target_alloc(target_pid, st.st_size);
	    if (addr == 0) {
		ERROR("E: target_alloc failed. pid=%d size=%ld\n", 
		      target_pid, st.st_size);
		continue;
	    }
	    if (set_data(target_pid, addr, p, st.st_size) < 0) {
		ERROR("E: load %s @ %p failed.\n", filename, (void *)addr);
		continue;
	    }
	    set_memvar(memname, addr, NULL);
	    NOTICE("load %s @ %p [%ld] %s\n", memname, (void *)addr, 
		   st.st_size, filename);

	} else if (strncmp(buf, "dl ", 3) == 0) {
	    char memname[4096];
	    char filename[4096];
	    bfd *abfd;
	    char *outbuf;
	    int outsize;
	    int addr;
	    struct symaddr *symaddr0 = NULL;

	    if (sscanf(buf, "dl %s %s\n", memname, filename) != 2) {
		ERROR("E: invalid dl line: %s", buf);
		continue;
	    }
	    INFO("dl pid=%d memvar=%s filename=%s\n", 
		 target_pid,
		 memname, filename);

	    abfd = bfd_openr(filename, NULL);
	    if (abfd == NULL) {
		bfd_perror("bfd_openr");
		continue;
	    }
	    bfd_check_format(abfd, bfd_object);
	    outsize = 0;
	    bfd_map_over_sections(abfd, bfd_map_section_alloc_size, &outsize);
	    outbuf = (char *)malloc(outsize);
	    if (outbuf == NULL) {
		ERROR("E: malloc failed. size=%d\n", outsize);
		continue;
	    }
	    memset(outbuf, 0, outsize);
	    /* XXX: size parameter */
	    bfd_map_over_sections(abfd, bfd_map_section_buf, outbuf);

	    /* global */
	    INFO("global symbol fixups %s\n", filename);
	    fixups(abfd, symaddrs, outbuf, outsize);

	    addr = target_alloc(target_pid, outsize);
	    if (addr == 0) {
		ERROR("E: target_alloc failed. pid=%d size=%d\n",
		      target_pid, outsize);
		continue;
	    }

	    bfd_read_symbols(abfd, addr, &symaddr0);
	    /* local */
	    INFO("local symbol fixups %s offset %p\n", filename, (void *)addr);
	    fixups(abfd, symaddr0, outbuf, outsize);
	    bfd_close(abfd);
	    
	    if (set_data(target_pid, addr, outbuf, outsize) < 0) {
		ERROR("E: dl %s @ %p failed.\n", filename, (void *)addr);
		continue;
	    }
	    set_memvar(memname, addr, symaddr0);
	    NOTICE("dl %s @ %p [%d] %s\n", memname, (void *)addr,
		   outsize, filename);

	} else if (strncmp(buf, "jmp ", 4) == 0) {
	    char addrinfo[4096];
	    char addr2info[4096];
	    int addr;
	    int addr2;
	    long jmp_relative;
	    char jmpbuf[5];

	    if (sscanf(buf, "jmp %s %s\n", addrinfo, addr2info) != 2) {
		ERROR("E: invalid jmp line: %s", buf);
		continue;
	    }
	    addr = lookup_addr(addrinfo);
	    addr2 = lookup_addr(addr2info);
	    INFO("jmp pid=%d addr=%p addr2=%p\n",
		 target_pid,
		 (void *)addr, (void *)addr);
	    jmp_relative = addr2 - (addr + 5);
	    INFO("jmp relative %ld (0x%08lx)\n", jmp_relative, jmp_relative);
	    jmpbuf[0] = 0xe9; /* jmp */
	    memcpy(jmpbuf+1, &jmp_relative, sizeof(int));
	    if (set_data(target_pid, addr, jmpbuf, sizeof(jmpbuf)) < 0) {
		ERROR("E: jmp %p %p failed.\n", (void *)addr, (void *)addr2);
		continue;
	    }
	    NOTICE("jmp %p %p\n", (void *)addr, (void *)addr2);

	} else {
	    ERROR("E: unknown command %s\n", buf);
	}
    }
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    DEBUG("detached %d\n", target_pid);
    exit(0);
}
