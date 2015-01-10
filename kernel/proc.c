#include "types.h"
#include "pstat.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

#define znew (z=36969*(z&65535)+(z>>16))
#define wnew (w=18000*(w&65535)+(w>>16))
#define MWC ((znew<<16)+wnew )
#define SHR3 (jsr^=(jsr<<17), jsr^=(jsr>>13), jsr^=(jsr<<5))
#define CONG (jcong=69069*jcong+1234567)
#define FIB ((b=a+b),(a=b-a))
#define KISS ((MWC^CONG)+SHR3)
#define SHR3 (jsr^=(jsr<<17), jsr^=(jsr>>13), jsr^=(jsr<<5))
#define CONG (jcong=69069*jcong+1234567)
#define FIB ((b=a+b),(a=b-a))
#define KISS ((MWC^CONG)+SHR3)
#define LFIB4 (c++,t[c]=t[c]+t[UC(c+58)]+t[UC(c+119)]+t[UC(c+178)])
#define SWB (c++,bro=(x<y),t[c]=(x=t[UC(c+34)])-(y=t[UC(c+19)]+bro))
#define UNI (KISS*2.328306e-10)
#define VNI ((long) KISS)*4.656613e-10
#define UC (unsigned char) /*a cast operation*/
#define UL  unsigned long

static int ndollars[NPROC];
static int udollars[NPROC];
static int dollars[NPROC];

static UL z=362436069, w=521288629, jsr=123456789, jcong=380116160;
static UL a=224466889, b=7584631, t[256];
//static UL x=0,y=0,bro; static unsigned char c=0;
/* Example procedure to set the table, using KISS: */
void settable(UL i1,UL i2,UL i3,UL i4,UL i5, UL i6)
{ int i; z=i1;w=i2,jsr=i3; jcong=i4; a=i5; b=i6;
  for(i=0;i<256;i=i+1) t[i]=KISS;
}
static uint temper(uint x)
{
    x ^= x>>11;
    x ^= x<<7 & 0x9D2C5680;
    x ^= x<<15 & 0xEFC60000;
    x ^= x>>18;
    return x;
}
uint lcg64_temper(long long *seed)
{
    *seed = 6364136223846793005ULL * *seed + 1;
    return temper(*seed >> 32);
}
struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

struct pstat p_stat;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
  settable(12345,65435,34221,12345,9983651,95746118);
  acquire(&ptable.lock);
  //init the stat structure
  int i;
  for(i=0; i<NPROC; i++) {
      p_stat.inuse[i] = 0;
      p_stat.pid[i] = 0;
      //p_stat.type[i] = 0; // 0 - spot, 1 - reserved
      p_stat.chosen[i] = 0;
      p_stat.time[i] = 0;
      p_stat.charge[i] = 0;
      dollars[i] = 0;
      udollars[i] = 0;
      ndollars[i] = 0;
      //p_stat.bid[i] = 0;
      //p_stat.cpu_time[i] = 0;
  }
  release(&ptable.lock);

}

// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;
  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;
  //init the proc as SPOT with bid as 0
  p->type = SPOT;
  p->cpu_time_per = 0;
  p->bid = 0;
  p->slot = (p - ptable.proc); //which slot in ptable is p at. 
  p->beginners_luck = BEGINNERS_LUCK_SCHED;

  //update pstat table
  p_stat.inuse[p->slot] = 1;
  p_stat.pid[p->slot] = p->pid;
  udollars[p->slot] = 0;
  ndollars[p->slot] = 0;
  dollars[p->slot] = 0;
  //p_stat.type[p->slot] = SPOT;
  //p_stat.bid[p->slot] = 0;
  //p_stat.cpu_time[p->slot] = 0;

  release(&ptable.lock);

  // Allocate kernel stack if possible.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;
  
  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;
  
  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];
  
  p = allocproc();
  acquire(&ptable.lock);
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;
  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  
  sz = proc->sz;
  if(n > 0){
    if((sz = allocuvm(proc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(proc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  proc->sz = sz;
  switchuvm(proc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;

  // Allocate process.
  if((np = allocproc()) == 0)
    return -1;

  // Copy process state from p.
  if((np->pgdir = copyuvm(proc->pgdir, proc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = proc->sz;
  np->parent = proc;
  *np->tf = *proc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(proc->ofile[i])
      np->ofile[i] = filedup(proc->ofile[i]);
  np->cwd = idup(proc->cwd);
 
  pid = np->pid;
  np->state = RUNNABLE;
  safestrcpy(np->name, proc->name, sizeof(proc->name));
  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *p;
  int fd;

  if(proc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(proc->ofile[fd]){
      fileclose(proc->ofile[fd]);
      proc->ofile[fd] = 0;
    }
  }

  iput(proc->cwd);
  proc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(proc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == proc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  proc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;

  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for zombie children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != proc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->state = UNUSED;
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        // re-init p to spot with 0 bid
        p->cpu_time_per = 0;
        p->type = SPOT;
        p->bid = 0;
        
        //clear pstat for this proc
        p_stat.inuse[p->slot] = 0;
        p_stat.pid[p->slot] = 0;
        //p_stat.type[p->slot] = SPOT;
        p_stat.chosen[p->slot] = 0;
        p_stat.time[p->slot] = 0;
        p_stat.charge[p->slot] = 0;
        dollars[p->slot] = 0;
        udollars[p->slot] = 0;
        ndollars[p->slot] = 0;
        //p_stat.bid[p->slot] = 0;
        //p_stat.cpu_time[p->slot] = 0;
        p->slot = -1;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || proc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(proc, &ptable.lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  int sl, max_sl;
  int beginner; 

  for(;;){
    // Enable interrupts on this processor.
    sti();
    beginner = 0;
    sl = -1;
    max_sl = -1;

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
        if(p->state != RUNNABLE || p->beginners_luck <= 0)
            continue;
        beginner = 1; 
        p->beginners_luck--; 
        break;
    }
    if (beginner) {
        //cprintf("chosen beginner pid [%d] \n", p->pid);
        beginner = 0;
        goto switcher;
    }
    p = 0; 
    max_sl = get_spot(); // sl is the spot proc with max bid. 
    //cprintf("max_sl = %d \n", max_sl);
    sl = get_lottery(max_sl);
    if (sl != -1) {
        p = &ptable.proc[sl];
        //cprintf("CPU [%d] slot [%d] ; chosen [%d] \n", cpu->id, p->slot, p->pid);
        goto switcher;
    }
    else
      goto no_luck;
   
  switcher:

    // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      proc = p;
      p_stat.chosen[proc->slot]++; 
      switchuvm(p);
      p->state = RUNNING;
      swtch(&cpu->scheduler, proc->context);
      switchkvm();
      p_stat.time[proc->slot] += 10; 
    
      if ( proc->type == SPOT) {
          ndollars[proc->slot] += (proc->bid*10);
    }
    else 
      ndollars[proc->slot] += (RESERVED_PROC_COST*10); 
    //if ndollars > 1000, add to udollars
    if (ndollars[proc->slot] >= 1000) {
      udollars[proc->slot]+= ndollars[proc->slot]/1000;
      ndollars[proc->slot] %= 1000;
    }
    /*
    if (udollars[proc->slot] >= 1000000) {
      dollars[proc->slot] += udollars[proc->slot]/1000000;
      udollars[proc->slot] %= 1000000;
    }
    */
    p_stat.charge[proc->slot]= udollars[proc->slot]; 

  no_luck:  
    // Process is done running for now.
      // It should have changed its p->state before coming back.
      proc = 0;
    release(&ptable.lock);
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state.
void
sched(void)
{
  int intena;

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(cpu->ncli != 1)
    panic("sched locks");
  if(proc->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = cpu->intena;
  swtch(&proc->context, cpu->scheduler);
  cpu->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  proc->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);
  
  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  if(proc == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }

  // Go to sleep.
  proc->chan = chan;
  proc->state = SLEEPING;
  sched();

  // Tidy up.
  proc->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];
  
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

void setspot (int bid) {
	acquire(&ptable.lock);
	proc->type = SPOT;
	proc->bid = bid;
  proc->cpu_time_per = 0;
  //p_stat.type[proc->slot] = SPOT;
	//p_stat.bid[proc->slot] = bid;
  //clear beginner's luck if bid>0
  if (bid > 0)
    proc->beginners_luck = 0;
  release(&ptable.lock);
}

int setreserve(int per) {
	if (per < 0 || per > 100)
		return -1;
	
	acquire(&ptable.lock);
	int total_per = 0; 
	struct proc* p;
	for(p=ptable.proc ; p < &ptable.proc[NPROC] ; p++) {
		if (p->type == RESERVED)
			total_per += p->cpu_time_per;
	}
  // check if current proc is already reserved and is trying to change its reservation
  if (proc->type == RESERVED) 
    total_per -= proc->cpu_time_per;

	if (total_per + per > 200) {
		release(&ptable.lock);
		return -1;
	}
	proc->type = RESERVED;
	proc->cpu_time_per = per;
  proc->bid = 0; 
	//p_stat.type[proc->slot] = RESERVED;
  //p_stat.cpu_time[proc->slot] = per;
  //clear beginners luck
  proc->beginners_luck = 0;
  release(&ptable.lock);
	return 0;
}

void pinfo( struct pstat** ps) {
    acquire(&ptable.lock);
    memmove(*ps, &p_stat, sizeof(struct pstat)); 
    release(&ptable.lock);
    return;
}

//returns spot process to run. 
int get_spot () {
    int maxbid = 0;
    struct proc* p;
    int min_chosen_sl = -1;
    int min_chosen = -1;
        
    for(p=ptable.proc ; p<&ptable.proc[NPROC] ; p++) {
        if (p->state != RUNNABLE || p->type != SPOT)
            continue;

        if (p->bid >= maxbid) {
            maxbid = p->bid;
            min_chosen = p_stat.chosen[p->slot];
            min_chosen_sl = p->slot;
        }
    }
    // check if there are multiple spots with bid=maxbid 
    for(p=ptable.proc ; p<&ptable.proc[NPROC] ; p++) {
        if (p->state != RUNNABLE || p->type != SPOT)
            continue;
        if (p->bid == maxbid) {
            if (p_stat.chosen[p->slot] < min_chosen) {
              min_chosen = p_stat.chosen[p->slot];
              min_chosen_sl = p->slot;
            }
            //cprintf("*****about to return slot %d ; min_chosen = %d\n", min_chosen_sl, min_chosen);
        }
    }
    //cprintf("about to return slot %d ; min_chosen = %d ; maxbid= %d\n", min_chosen_sl, min_chosen, maxbid);
    return min_chosen_sl;
}

//perform lottery among available threads & pick winner
int get_lottery (int max_sl) {
  // first need to know the list of RUNNABLE threads and total per reserved by them.
  // assuming that calling function has acquire ptable.lock
  struct proc* p;
  
  int win_lottery = KISS % 200 + 1;
  if (win_lottery < 1 || win_lottery > 200)
    cprintf("Error! \n");

  //cprintf("%d :win lottery = %d ; lottery pot = %d \n", cpu->id, win_lottery, lottery_pot);
  int tickets = 0;
  for (p=ptable.proc ; p < &ptable.proc[NPROC] ; p++) {
    if (p->state != RUNNABLE) 
      continue;
    if (p->type == RESERVED) {
      tickets += p->cpu_time_per;
      if (win_lottery < tickets) {
        return p->slot;
      }
    }
  }
  //looks like no reserved won the lottery
  return max_sl;
}

