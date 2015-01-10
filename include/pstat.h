#include "param.h"

struct pstat {
    int inuse[NPROC]; // whether this slot of the process process table is in use (1 or 0)
    int pid[NPROC];   // the PID of each process
    int chosen[NPROC]; // the number of times the process was chosen to run
    int time[NPROC]; // the number of ms the process has run
    int charge[NPROC]; // charge will be same as udollars. (late project spec change)
    //int dollars[NPROC]; //maintaining charge as dollars & micro-dollars. 
    //int udollars[NPROC]; 
    //int ndollars[NPROC];
    //int type[NPROC];
    //int bid[NPROC];
    //int cpu_time[NPROC];
};
