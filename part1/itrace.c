#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset, strncmp, strsignal
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>
#include <asm/ptrace.h>
#include <udis86.h>



#define LINELEN   81

extern char* __progname;

/** The process ID to trace. */
long int tr_pid = 0;

/** pointer to user-entered string */
char* usercmd = NULL;

static void do_sniff();
static void do_usage(void);
static void handle_singelstep();
static void init_attach(char*);
static void create_interpreter(void);
static void quit(void);
static void kill_trace_session(void);
static void handle_continue(int*);

static void 
do_usage()
{
  fprintf(stderr,
	  "Usage: %s -p [pid]\n Command: exit, kill, cont...\n",
	  __progname);
  return;
}

static void
create_interpreter()
{
  usercmd = calloc(LINELEN, sizeof(char));
  if(NULL==usercmd)
  {
    fprintf(stderr,
	    "failed to allocate memory for user command line\n");
    exit(-3);
  }
  return;
}

static void
init_attach(char* tpid)
{
  int s = 0;
  long p_ret = 0;
  pid_t p = 0;
  int attach_status = 0;

  tr_pid = strtol(tpid, NULL, 10);

  fprintf(stdout,
	  "[snyfer] tracing process %ld\n",
	  tr_pid);

  p_ret = ptrace(PTRACE_ATTACH,
		 tr_pid,
		 NULL, //ignored
		 NULL); //ignored
  if(-1==p_ret)
  {
    fprintf(stderr,
	    "[snyfer] failed to attach to child, exiting...\n");
    exit(-1);
  }

  p = waitpid(tr_pid,
	      &attach_status,
	      WUNTRACED | WCONTINUED);

  if(WIFSTOPPED(attach_status))
  {
    s = WSTOPSIG(attach_status);
    fprintf(stdout,
	    "Successful attach. Child stopped by signal %d : %s\n", 
	    s,
	    strsignal(s));
  }else{
    fprintf(stdout,
	    "failed to stop / attach target process\n");
    exit(-2);
  }
  return;
}

// Function to read and disassemble one instrution after ptrace stopped on singlestep
// by Xiao Lin
// reference: http://www.aryweb.nl/2013/05/25/ptrace-timing-analysis-by-disassembling/
static void handle_singelstep() {
  struct user_regs_struct regfile;
  ptrace(PTRACE_GETREGS, tr_pid, NULL, &regfile);
  unsigned long addr = regfile.eip;
  fprintf(stdout, "Address = 0x%08lx\n", addr);
  // x86 system have instruction length upto 15 bytes, but ptrace only return 4bytes, so this is an approximation
  unsigned long long data = ptrace(PTRACE_PEEKTEXT, tr_pid, addr, NULL);
  fprintf(stdout, "Data = 0x%016llx\n", data);
  ud_t ud_obj;
  unsigned char buff[8];
  memcpy(buff, (char*)&data, sizeof(long long));

  // setup udis86
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, 32);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_input_buffer(&ud_obj, buff, 8);

  // disassemble and print
  if (ud_disassemble(&ud_obj) != 0) {
    printf("Disassemble:  %s  %s\n", ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
  }

  return;
}

static void
kill_trace_session()
{
  //send child PTRACE_KILL
  fprintf(stdout,
	  "killing child and exiting...\n");
  ptrace(PTRACE_KILL,
	 tr_pid,
	 NULL,
	 NULL);
  free(usercmd);
  usercmd = NULL;
  exit(0);
}

static void
quit()
{
  //cleanup and quit
  fprintf(stdout,
	  "Tracer will quit. Traced process %ld will continue running.\n",
	  tr_pid);
  ptrace(PTRACE_DETACH,
	 tr_pid,
	 NULL,
	 NULL);
  free(usercmd);
  usercmd = NULL;
  exit(0);  
}

/**
  int* i = 0;
  int a = 100;
  int* x = &a;
  int y = (*x) + 1; 
  a = 200;

 */
static void
handle_continue(int* cont)
{
  long p_ret = 0;
  pid_t p = 0;
  int attach_status = 0;
  int s = 0;

  //continue to the next system call (or end of this one)
  p_ret = ptrace(PTRACE_SINGLESTEP,
		 tr_pid,
		 NULL,
		 NULL);
  p = waitpid(tr_pid, 
	      &attach_status, 
	      WUNTRACED | WCONTINUED);
  if(-1==p) 
  {
    perror("waitpid");
    exit(-5);
  }
      
  if(WIFEXITED(attach_status))
  {
    fprintf(stdout, "exited, status=%d\n", WEXITSTATUS(attach_status));
  }else if (WIFSIGNALED(attach_status)){
    s = WTERMSIG(attach_status);
    fprintf(stdout,"killed by signal %d : %s\n", 
	    s,
	    strsignal(s));
  }else if (WIFSTOPPED(attach_status)){
    s = WSTOPSIG(attach_status);
    fprintf(stdout,"stopped by signal %d : %s\n", 
	    s,
	    strsignal(s));
    if(SIGTRAP==WSTOPSIG(attach_status) ||
       SIGSTOP==WSTOPSIG(attach_status))
    {
      handle_singelstep();
    }else{
      fprintf(stderr, "unrecognized signal state for stopped @ syscall\n");
    }
  } else if (WIFCONTINUED(attach_status)) {
    fprintf(stdout,"continued\n");
  }else{
    fprintf(stdout, "unrecognized stop condition\n");
  }

  if(!WIFEXITED(attach_status) && !WIFSIGNALED(attach_status))
  {
    *cont = 1;
  }else{
    fprintf(stdout, "setting stop flag\n");
    *cont = 0;
  }
  return;
}

/**
long 
ptrace(enum __ptrace_request request, 
       pid_t pid,
       void *addr, 
       void *data) 
 */
static void 
do_sniff()
{
  int should_continue = 1; //TRUE

  do
  {
    fprintf(stdout,
	    "snyfer> ");
    usercmd = fgets(usercmd, LINELEN, stdin);
    if(NULL == usercmd)
    {
      fprintf(stderr,
	      "problem reading input\n");
      exit(-4);
    }

    if(0==strncmp(usercmd, "quit", 4) ||
       0==strncmp(usercmd, "exit", 4)){
      quit();
    }else if(0==strncmp(usercmd, "run", 3)){
      fprintf(stdout, "not implemented\n");
    }else if(0==strncmp(usercmd, "kill", 4)){
      kill_trace_session();
    }else if(0==strncmp(usercmd, "cont", 4)){
      handle_continue(&should_continue);
    }else{
      handle_continue(&should_continue); // assume default is cont
    }
    memset(usercmd, '\0', LINELEN);
  } while(1==should_continue);

  return;
}

/**
 * ./itrace -p [PID]
 *
 * opens an interactive session where you can trace a process single-step
 * the instructions will be disassembled via udis86
 *
 */
int main(int argc,
	 char* argv[])
{
  if(3==argc)
  {
    init_attach(argv[2]);
    create_interpreter();
    do_sniff();
  }else{
    do_usage();
    return -1;
  }

  return 0;
}
