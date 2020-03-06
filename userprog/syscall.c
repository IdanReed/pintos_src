#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define SYS_CALL_COUNT 13
#define SUPPORTED_ARGS 3
#define BUFF_MAX 150
#define ERROR -1

static void syscall_handler (struct intr_frame *);
static void copy_into_kernel (void * dsk_k, const void * src_u, size_t size);
static int syscall_halt (void);
static int syscall_exit (int status);
static int syscall_exec (const char *cmd_line);
static int syscall_wait (tid_t pid);
static int syscall_create (const char *file, unsigned initial_size);
static int syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write (int fd, const void *buffer, unsigned size);
static int syscall_seek (int fd, unsigned position);
static int syscall_tell (int fd);
static int syscall_close (int fd);

typedef int syscall_fn (uint32_t, uint32_t, uint32_t);
static struct file_descriptor * lookup_file (uint32_t fd); 

static struct lock filesys_lock;

struct syscall 
{
  int arg_count;
  syscall_fn * function;
};

static const struct syscall call_table[] = 
{
  {0, (syscall_fn*) syscall_halt},
  {1, (syscall_fn*) syscall_exit},
  {1, (syscall_fn*) syscall_exec},
  {1, (syscall_fn*) syscall_wait},
  {2, (syscall_fn*) syscall_create},
  {1, (syscall_fn*) syscall_remove},
  {1, (syscall_fn*) syscall_open},
  {1, (syscall_fn*) syscall_filesize},
  {3, (syscall_fn*) syscall_read},
  {3, (syscall_fn*) syscall_write},
  {2, (syscall_fn*) syscall_seek},
  {1, (syscall_fn*) syscall_tell},
  {1, (syscall_fn*) syscall_close},
};

/* Make sure every syscall is implemented */
_Static_assert(sizeof(call_table) / sizeof(struct syscall) == SYS_CALL_COUNT,
    "call_table does not match syscall enum amount");

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint8_t call_number;
  uint32_t args[SUPPORTED_ARGS];
  struct syscall call;

  copy_into_kernel(&call_number, (const void *) f->esp, sizeof call_number);

  /* Make sure the call number is valid */
  if (call_number > SYS_CALL_COUNT)
  {
    //Botched
    printf("invalid syscall!\n");
    thread_exit();
  }
 
  /* Get the corresponding syscall */
  call = call_table[call_number];

  /* Verify that it has a supported amount of args. Prevents developer error*/
  ASSERT(call.arg_count >= 0 && call.arg_count <= SUPPORTED_ARGS);
  memset(args, 0, sizeof args);

  /* Copy the args */
  copy_into_kernel(&args, (uint32_t *) f->esp + 1, (sizeof *args) * call.arg_count);

  /* Call syscall */
  f->eax = call.function(args[0], args[1], args[2]);
}

static int 
min (int a, int b)
{
  return a < b ? a : b;
}

static bool 
is_valid_mem_area (const void * src_u, size_t size)
{
  struct thread * tc;
  const uint8_t * src_;

  tc = thread_current();
  src_ = src_u;

  return (src_u != NULL
       && is_user_vaddr (src_)
       && pagedir_get_page (tc->pagedir, src_) != NULL
       && is_user_vaddr (src_ + size)
       && pagedir_get_page (tc->pagedir, src_ + size) != NULL);
}


static void 
copy_into_kernel (void * dst_k, const void * src_u, size_t size)
{
  uint8_t * dst_;
  const uint8_t * src_;

  dst_ = dst_k;

  if (!is_valid_mem_area(src_u, size))
  {
    thread_exit();
  }

  src_ = pagedir_get_page (thread_current ()->pagedir, src_u);

  for (; size > 0; size--, dst_++, src_++)
    *dst_ = *src_;
}

static int syscall_halt (void)
{
  shutdown_power_off ();
}

static int syscall_exit (int status)
{
  thread_current()->exit_status = status;
  thread_exit();
}

static int syscall_exec (const char *cmd_line)
{
  tid_t tid;

  // TODO: Validate filename
  
  lock_acquire (&filesys_lock);
  tid = process_execute (cmd_line);
  lock_release (&filesys_lock);

  return tid;
}

static int syscall_wait (tid_t pid)
{
  return process_wait (pid);
}

static int syscall_create (const char *file, unsigned initial_size)
{
  bool res;

  // TODO: Validate filename
  
  lock_acquire (&filesys_lock);
  res = filesys_create (file, initial_size);
  lock_release (&filesys_lock);

  return res;
}

static int syscall_remove (const char *file)
{
  bool res;

  // TODO: Validate filename

  lock_acquire (&filesys_lock);
  res = filesys_remove (file);
  lock_release (&filesys_lock);

  return res;
}

static int syscall_open (const char *file)
{
  struct file * f;
  struct file_descriptor * fd;
  struct thread * tc;

  // TODO: Validate the string

  tc = thread_current ();

  lock_acquire (&filesys_lock);
  f = filesys_open(file);
  lock_release (&filesys_lock);

  if (!f)
  {
    thread_exit ();
  }

  /* Make new file descriptor */
  fd = malloc (sizeof(struct file_descriptor)); 
  
  if (!fd)
  {
    return ERROR;
  } 

  fd->file = f;
  fd->handle = tc->current_desc;
  tc->current_desc++;
  list_push_back (&tc->file_decs, &fd->elem); 

  return fd->handle;
}

static int syscall_filesize (int fd)
{
  struct file * f;
  off_t length;

  f = lookup_file (fd)->file;

  lock_acquire (&filesys_lock);

  length = file_length (f);

  lock_release (&filesys_lock);

  return length;
}

static int syscall_read (int fd, void *buffer, unsigned size)
{
  struct file * file_to_read;
  uint8_t * buf;
  off_t amount_read;

  buf = buffer;
  amount_read = 0;

  if (!is_valid_mem_area (buffer, size))
  {
    thread_exit ();
  }

  if (fd == STDIN_FILENO)
  {
    while (size > 0)
    {
      *buf = input_getc ();
      size--;
      amount_read++;
      buf++;
    }
  }
  else 
  {
    file_to_read = lookup_file (fd)->file;

    lock_acquire (&filesys_lock);

    amount_read = file_read (file_to_read, buf, size);

    lock_release (&filesys_lock);
  }

  return amount_read;
}

static int syscall_write (int fd, const void *buffer, unsigned size)
{
  const uint8_t * buf;
  int total_written_bytes;
  int partial_written_bytes;
  int amt_to_write;
  struct file * file_to_write;

  buf = buffer;
  partial_written_bytes = 0;
  total_written_bytes = 0;
  amt_to_write = 0;
  file_to_write = NULL;

  if (fd != STDOUT_FILENO)
  {
    file_to_write = lookup_file (fd)->file;
  }

  if (!is_valid_mem_area (buf, size))
  {
    /* Gave us a bad address */
    thread_exit();
  }

  lock_acquire (&filesys_lock);

  while (size > 0)
  {
    amt_to_write = min (size, BUFF_MAX);


    if (fd == STDOUT_FILENO)
    {
      putbuf ((const char*) buf, amt_to_write);
      partial_written_bytes = amt_to_write;
    }
    else
    {
      partial_written_bytes = file_write (file_to_write, buf, amt_to_write);
    }

    total_written_bytes += partial_written_bytes;

    /* This was a partial write, need to quit */
    if (partial_written_bytes != amt_to_write)
    {
      break;
    }

    size -= partial_written_bytes;
    buf += partial_written_bytes;
  }

  lock_release (&filesys_lock);

  return total_written_bytes;
}
static int syscall_seek (int fd, unsigned position)
{
  struct file * f;

  f = lookup_file (fd)->file;

  lock_acquire (&filesys_lock);
  file_seek (f, position);
  lock_release (&filesys_lock);

  return 0;
}

static int syscall_tell (int fd)
{
  struct file * f;
  off_t res;

  f = lookup_file (fd)->file;

  lock_acquire (&filesys_lock);
  res = file_tell (f);
  lock_release (&filesys_lock);

  return res;

}

static int syscall_close (int fd)
{
  struct file_descriptor * desc;

  desc = lookup_file (fd);

  lock_acquire (&filesys_lock);
  file_close (desc->file);
  lock_release (&filesys_lock);
  list_remove (&desc->elem);
  free (desc);
  return 0;
}

static struct file_descriptor * 
lookup_file (uint32_t fd) 
{
  struct thread * tc;
  struct list_elem * e;
  struct file_descriptor * desc;

  tc = thread_current();

  for (e = list_begin (&tc->file_decs); 
       e != list_end (&tc->file_decs); 
       e = list_next (e))
  {
    desc = list_entry (e, struct file_descriptor, elem);  
    if (desc->handle == fd){
      return desc;
    }
  }

  /* Trying to lookup a file that the thread doesn't have */
  thread_exit();
}
