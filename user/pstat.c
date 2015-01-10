#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"
#include "syscall.h"
#include "traps.h"
#include "param.h"
#include "pstat.h"
int stdout = 1;
int main (int argc, char** argv) {
    //struct pstat* ps= malloc(sizeof(struct pstat));
    struct pstat ps;
    int i; 
    if (spot(100) <0) 
      exit();
    if (getpinfo(&ps) < 0) {
        printf(2, "unable to get pstat \n");
        exit();
    }
    //printf(1, "slot\tinuse\tpid\ttype\tbid\tcpu_t\tchosen\ttime\tcharge\n");
    for (i=0; i<NPROC; i++) {
        //printf(1, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", i, ps.inuse[i], ps.pid[i], ps.type[i], ps.bid[i], ps.cpu_time[i], ps.chosen[i], ps.time[i], ps.charge[i]);
    }
    exit();
}
    
