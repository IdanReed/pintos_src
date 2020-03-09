#include "userprog/process.h"
#include <list.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct process_info
{
  char * file_name;
  struct child * child_node;
  bool success;
  struct semaphore started;

  const char * usr_args;
  struct list parsed_args;
};


struct usr_arg_info
{
  struct list_elem elem;
  char * arg;
  int size;
  char * arg_vaddr;
};

static thread_func start_process NO_RETURN;
static bool load (struct process_info *, void (**eip) (void), void **esp);
static void free_child (struct child * child_node);


static void debug_print_args (struct process_info * p_info);
static bool parse_args (struct process_info * p_info);
static void free_proccess_info_mem (struct process_info *);


/* Ref counting inspired by
https://github.com/yuan901202/pintos_3/blob/master/src/threads/thread.h
*/
static void free_child (struct child * child_node)
{
  int new_count;

  lock_acquire (&child_node->lock);
  new_count = --child_node->ref_count;
  lock_release (&child_node->lock);

  if (new_count == 0)
  {
    /* We have no more references so its safe to free the memory */
    free (child_node);
  }
}

static void
debug_print_args (struct process_info * p_info)
{
  struct list_elem * e;
  struct usr_arg_info * u_arg;

  printf("User Args: \n");
  for (	e = list_begin (&p_info->parsed_args);
	e != list_end (&p_info->parsed_args);
	e = list_next (e)
      )
    {
      u_arg = list_entry (e, struct usr_arg_info, elem);
      printf("\t%.*s\n", u_arg->size, u_arg->arg);
    }
}

static bool
parse_args (struct process_info * p_info)
{
  int cur_index;
  char cur;
  int arg_start;

  struct usr_arg_info * prev_arg;
  struct usr_arg_info * file_arg;

  prev_arg = malloc(sizeof(struct usr_arg_info));
  prev_arg->arg = p_info->usr_args;

  list_init (&p_info->parsed_args);
  list_push_back (&p_info->parsed_args, &prev_arg->elem);

  arg_start = 0;
  cur_index = 0;
  while (cur_index < PGSIZE) {
    cur = p_info->usr_args[cur_index];

    if (cur == '\0'){
      prev_arg->size = cur_index - arg_start;
      break;
    }
    else if (cur == ' '){
      prev_arg->size = cur_index - arg_start;
      prev_arg = malloc(sizeof(struct usr_arg_info));
      list_push_back (&p_info->parsed_args, &prev_arg->elem);

      while (cur == ' ') {
        cur_index++;
        cur = p_info->usr_args[cur_index];
      }

      prev_arg->arg = &p_info->usr_args[cur_index];
      arg_start = cur_index;
    }
    cur_index++;
  }

  file_arg = list_entry (
      list_front (&p_info->parsed_args),
      struct usr_arg_info,
      elem
    );

  p_info->file_name = malloc (sizeof (file_arg->size+1));
  memcpy (p_info->file_name, file_arg->arg, file_arg->size);
  p_info->file_name[file_arg->size] = '\0';

  //debug_print_args (p_info);
  return true;
}

static void
free_proccess_info_mem (struct process_info * p_info)
{
  free (p_info->file_name);
  free (p_info->usr_args);

  while (!list_empty (&p_info->parsed_args))
    {
      free (
        list_entry (list_pop_front (&p_info->parsed_args),
        struct usr_arg_info,
        elem)
      );
    }

}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *usr_args)
{
  struct process_info * p_info;
  tid_t tid;

  p_info = malloc (sizeof (struct process_info));

  /* Save out usr args to page */
  p_info->usr_args = palloc_get_page (0);

  if (p_info->usr_args == NULL)
    return false;
  strlcpy (p_info->usr_args, usr_args, PGSIZE);

  parse_args (p_info);

  sema_init (&p_info->started, 0);
  p_info->success = false;


  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (p_info->file_name, PRI_DEFAULT, start_process, p_info);

  if (tid == TID_ERROR){
    return TID_ERROR;
  }

  /* Wait for process_start to run */
  sema_down (&p_info->started);

  /* Exit if it didn't create successfully */
  if (!p_info->success)
    return TID_ERROR;

  //debug_print_args (p_info);


  /* Add as child process */
  list_push_back (&thread_current ()->children, &p_info->child_node->elem);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void * process_info_)
{
  struct process_info *process_info = process_info_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (process_info, &if_.eip, &if_.esp);

  /* Create the child node so that it can be added to the parent */
  if (success)
  {
    process_info->child_node = malloc(sizeof *process_info->child_node);
    thread_current ()->child_node = process_info->child_node;
    success = process_info->child_node != NULL;
  }

  /* Setup the child node after sucessful allocation */
  if(success)
  {
    process_info->child_node->tid = thread_current ()->tid;
    process_info->child_node->exit_status = -1;
    process_info->child_node->ref_count = 2;
    sema_init (&process_info->child_node->dead, 0);
    lock_init (&process_info->child_node->lock);
  }

  process_info->success = success;
  sema_up (&process_info->started);

  /* If load failed, quit. */
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread * tc;
  struct list_elem * e;
  struct child * child_node;
  int exit_status;

  tc = thread_current ();
  exit_status = -1;

  for (e = list_begin (&tc->children);
       e != list_end (&tc->children);
       e = list_next(e))
  {
    child_node = list_entry (e, struct child, elem);

    if (child_node->tid == child_tid)
    {
      /* Wait for child to die. (oof that's a bit morbid) */
      sema_down (&child_node->dead);

      /* Use our child's exit status as return value */
      exit_status = child_node->exit_status;

      /* Remove child from children list */
      list_remove (e);

      /* Free the child */
      free_child (child_node);

      break;
    }
  }

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list_elem * e;

  if (cur->child_node != NULL)
  {
    printf ("%s: exit(%d)\n", cur->name, cur->child_node->exit_status);

    /* Notify our parent of our death */
    sema_up (&cur->child_node->dead);

    /* Lose a reference and potentially deallocate */
    free_child (cur->child_node);
  }

  /* Free up our references to children */
  for (e = list_begin (&cur->children);
       e != list_end (&cur->children);
       e = list_remove(e))
  {
    /* Remove our reference to the child */
    free_child (list_entry (e, struct child, elem));
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
void stack_usr_args (struct process_info * p_info, void (**esp));

int stack_count = 0;

void
stack_usr_args (struct process_info * p_info, void (**esp))
{
  struct thread * t;

  struct list_elem * e;
  struct usr_arg_info * u_arg;

  /* Push strings and store vaddrs */
  for (	e = list_back (&p_info->parsed_args);
	e != list_head (&p_info->parsed_args);
	e = list_prev (e)
      )
  {
    u_arg = list_entry (e, struct usr_arg_info, elem);
    *esp -= u_arg->size + 1;
    memcpy (*esp, u_arg->arg, u_arg->size);

    /* Null terminate string */
    char nul = '\0';
    memcpy(*esp - 1, &nul, sizeof(char));

    u_arg->arg_vaddr = *esp;
  }

  /* Word align */
  while ((int)*esp%4 != 0)
  {
    *esp -= 1;
    char czero = 0;
    memcpy(*esp, &czero, 1);
  }

  /* Null ptr sentinel */
  int zero = 0;
  *esp-=sizeof(int);
  memcpy(*esp, &zero, sizeof(int));


  /* Push string ptrs */
  if (!list_empty (&p_info->parsed_args))
  {
    for ( e = list_back (&p_info->parsed_args);
          e != list_head (&p_info->parsed_args);
          e = list_prev (e)
	    )
    {
      u_arg = list_entry (e, struct usr_arg_info, elem);
      *esp -= sizeof(int);
      memcpy(*esp, &u_arg->arg_vaddr, sizeof(int));
    }
  }

  /* Argv ptr */
  int argv_ptr = *esp;
  *esp-=sizeof(int);
  memcpy(*esp,&argv_ptr,sizeof(int));

  /* Argc */
  int argc = list_size (&p_info->parsed_args);
  *esp-=sizeof(int);
  memcpy(*esp,&argc,sizeof(int));

  /* Return addres */
  *esp-=sizeof(int);
  memcpy(*esp,&zero,sizeof(int));

  free_proccess_info_mem (p_info);

}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct process_info * p_info, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (p_info->file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", p_info->file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", p_info->file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  stack_usr_args (p_info, esp);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE - 12;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
