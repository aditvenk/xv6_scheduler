// Do not modify this file. It will be replaced by the grading scripts
// when checking your project.

#include "types.h"
#include "stat.h"
#include "user.h"
#include "pstat.h"

#define RUN (300)

void assert(int check) {
  if (!check) {
    printf(2, "assert fails (check = %d)\n", check);
    exit();
  }
}

void child(int percent, int bid) {
  int start = uptime();
  int sum = 0;
  if (percent) {
    printf(1, "PID %d reserves %d\n", getpid(), percent);
    reserve(percent);
  } else {
    printf(1, "PID %d bids %d\n", getpid(), bid);
    spot(bid);
  }
  sleep(10);

  while(uptime() - start < RUN) {
    sum++; // spin
  }

  exit();
}

int main(int argc, char *argv[]) {
  int i;
  struct pstat ps;
  int start = uptime();
  printf(1, "Start Test\n");
  
  for(i=0; i<6; i++) {
    int pid = fork();
    assert(pid >= 0);
    if(pid == 0) {
      if (i < 4)
        child(200, 0);
      else if (i == 4)
        child(0, 50);
      else if (i == 5)
        child(0, 50);
    }
  }

  while(uptime() - start < RUN)
    ; // spin

  // debug info
  getpinfo(&ps);
  for(i=0; i<NPROC; i++) {
    if (ps.inuse[i]) {
      printf(1, "inuse=%d, pid=%d, chosen=%d, time=%d, charge=%d\n",
             ps.inuse[i], ps.pid[i], ps.chosen[i], ps.time[i], ps.charge[i]);
    }
  }

  // cleanup
  for(i=0; i<6; i++) {
    wait();
  }
  exit();
}
