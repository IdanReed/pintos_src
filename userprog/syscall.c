#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define SYS_CALL_COUNT 13
#define SUPPORTED_ARGS 3
#define BUFF_MAX 150

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
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint8_t call_number;
  uint32_t args[SUPPORTED_ARGS];
  struct syscall call;

  copy_into_kernel(&call_number, (const void *) f->esp, sizeof call_number);

  printf("got syscall: %d\n", call_number);

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

static int 
max (int a, int b)
{
  return a > b ? a : b;
}

static bool 
is_valid_mem (const void * src_u)
{
  return (src_u != NULL
       && is_user_vaddr (src_u)
       && pagedir_get_page (thread_current ()->pagedir, src_u) != NULL);
}


static void 
copy_into_kernel (void * dst_k, const void * src_u, size_t size)
{
  uint8_t * dst_;
  const uint8_t * src_;

  dst_ = dst_k;
  src_ = src_u;

  /* Copy into kernel location */
  for(; size > 0; size--, dst_++, src_++)
  {
    if(!is_valid_mem(src_))
    {
      thread_exit();
    }
    *dst_ = *src_;
  }
}

static int syscall_halt (void){}
static int syscall_exit (int status)
{
  thread_current()->exit_status = status;
  thread_exit();
}
static int syscall_exec (const char *cmd_line){}
static int syscall_wait (tid_t pid){}
static int syscall_create (const char *file, unsigned initial_size){}
static int syscall_remove (const char *file){}
static int syscall_open (const char *file){}
static int syscall_filesize (int fd){}
static int syscall_read (int fd, void *buffer, unsigned size){}
static int syscall_write (int fd, const void *buffer, unsigned size)
{
  const uint8_t * buf;
  int total_written_bytes;
  int partial_written_bytes;
  int amt_to_write;
  struct file * file_to_write = NULL;

  buf = buffer;
  partial_written_bytes = 0;
  total_written_bytes = 0;
  amt_to_write = 0;

  if (fd != STDOUT_FILENO)
  {
    file_to_write = lookup_file (fd)->file;
  }

  while (size > 0)
  {
    /* Gave us a bad address */
    if (!is_valid_mem (buf))
    {
      thread_exit();
    }

    amt_to_write = min (size, BUFF_MAX);

    if (fd == STDOUT_FILENO)
    {
      putbuf (buf, amt_to_write);
      partial_written_bytes = amt_to_write;
    }
    else
    {
      //partial_written_bytes = write_file (file_to_write, buf, amt_to_write);
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

  return total_written_bytes;
}
static int syscall_seek (int fd, unsigned position){}
static int syscall_tell (int fd){}
static int syscall_close (int fd){}

static struct file_descriptor * 
lookup_file (uint32_t fd) 
{

}
