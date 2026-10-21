/* C3 Candidate B B-01, isolated Darwin-only, disposable SYNTHETIC processes.
 * There is deliberately NO group signal syscall, no command input and no
 * ability to target existing host PID/PGID. G2 remains BLOCK.
 *
 * Owner -> Anchor (direct owned PG leader), Controller (different group).
 * Controller -> Worker (direct child, posix_spawn group join before exec).
 * Worker READY -> Controller observation -> Owner kernel PPID/PGID/SID check
 * -> Owner grant -> Controller opens Worker gate -> Controller waitpid.
 */
#ifndef __APPLE__
#include <stdio.h>
int main(void) { fputs("C3B_NOT_RUN_NON_DARWIN\n", stderr); return 77; }
#else
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
enum { M_POSITIVE=1, M_OWNER_MISSING=2, M_SPAWN_MISSING=3,
       M_CROSS_SESSION=4, M_GATE_DENIED=5 };
enum { SETUP_MAGIC=0x43334231, READY_MAGIC=0x43334232,
       PROPOSAL_MAGIC=0x43334233, FINAL_MAGIC=0x43334234 };
typedef struct { int magic, mode; pid_t anchor, sid; } Setup;
typedef struct { int magic; pid_t pid, ppid, pgid, sid; } WorkerReady;
typedef struct {
    int magic, seq, attempted, started, failure;
    pid_t controller, ctrl_pgid, ctrl_sid;
    pid_t worker, reported_parent, worker_pgid, worker_sid;
} Proposal;
typedef struct {
    int magic, seq, waited, status, gate_opened;
    pid_t worker;
} Final;
typedef struct { pid_t pid; int input, output, reaped, raw; } Child;
typedef struct {
    int anchor_held, controller_outside, sid_distinct, spawn_attempted,
        worker_spawned, join_verified, parentage_verified, owner_granted,
        gate_opened, workload_started, controller_waited, cleanup_complete;
} Observed;

static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static long remaining(long long end) {
    long long delta = end - now_ms();
    return delta <= 0 ? 0 : delta > 5000 ? 5000 : (long)delta;
}
static void pause_10ms(void) {
    struct timespec t = {.tv_sec=0,.tv_nsec=10000000L};
    while (nanosleep(&t,&t) < 0 && errno == EINTR) {}
}
static int close_fd(int *p) {
    if (*p < 0) return 1;
    int v=*p; *p=-1;
    return close(v)==0;
}
static int private_pipe(int p[2]) {
    if (pipe(p)) return 0;
    if (fcntl(p[0],F_SETFD,FD_CLOEXEC) < 0 ||
        fcntl(p[1],F_SETFD,FD_CLOEXEC) < 0) {
        close(p[0]);close(p[1]);p[0]=p[1]=-1;return 0;
    }
    return 1;
}
static int wait_read(int fd, void *out, size_t n, long long deadline) {
    size_t used=0;
    unsigned char *b=(unsigned char*)out;
    while (used<n && remaining(deadline)>0) {
        struct pollfd p={.fd=fd,.events=POLLIN|POLLHUP};
        long left=remaining(deadline);
        int r=poll(&p,1,(int)(left>100?100:left));
        if (r<0 && errno==EINTR) continue;
        if (r<=0) { if (r==0) continue; return 0; }
        ssize_t got=read(fd,b+used,n-used);
        if (got<0 && errno==EINTR)continue;
        if (got<=0)return 0;
        used+=(size_t)got;
    }
    return used==n;
}
static int write_once(int fd,const void *data,size_t n) {
    /* All frames are < PIPE_BUF, there is one writer per private pipe. */
    for (;;) {
        ssize_t r=write(fd,data,n);
        if (r<0 && errno==EINTR)continue;
        return r==(ssize_t)n;
    }
}
static int send_gate(int fd,char c) { return write_once(fd,&c,1); }
static int receive_gate(int fd,char *c,long long end) {
    return wait_read(fd,c,1,end);
}
static int fail(const char *reason) {
    fprintf(stderr,"C3B_BLOCK phase=%s\n",reason);
    return 70;
}
static int waitable_signals(void) {
    struct sigaction a, actual;
    memset(&a,0,sizeof a);
    a.sa_handler=SIG_DFL;
    if (sigemptyset(&a.sa_mask) || sigaction(SIGCHLD,&a,NULL) ||
        sigaction(SIGCHLD,NULL,&actual) ||
        actual.sa_handler!=SIG_DFL ||
        (actual.sa_flags&SA_NOCLDWAIT)) return 0;
    a.sa_handler=SIG_IGN;
    return sigaction(SIGPIPE,&a,NULL)==0;
}
static int private_root(const char *root,const char *binary,int *out) {
    if (!root || root[0]!='/' || !binary) return 0;
    size_t len=strlen(root);
    if (strncmp(root,binary,len) || strcmp(binary+len,"/c3_candidate_b_native"))
        return 0;
    int fd=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0)return 0;
    struct stat st;
    if (fstat(fd,&st) || !S_ISDIR(st.st_mode) ||
        st.st_uid!=geteuid() || (st.st_mode&0077)) goto bad;
    int mark=openat(fd,"C3B_TEST_MARKER",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (mark<0)goto bad;
    char data[16]={0};
    ssize_t n=read(mark,data,sizeof data);
    int valid=!fstat(mark,&st) && S_ISREG(st.st_mode) &&
              st.st_uid==geteuid() && st.st_nlink==1 &&
              n==9 && !memcmp(data,"synthetic",9);
    (void)close(mark);
    if (!valid) goto bad;
    int exe=openat(fd,"c3_candidate_b_native",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(exe<0)goto bad;
    valid=!fstat(exe,&st) && S_ISREG(st.st_mode) &&
          st.st_uid==geteuid() && st.st_nlink==1 && (st.st_mode&0111);
    close(exe);
    if(!valid)goto bad;
    *out=fd;
    return 1;
bad:
    close(fd); return 0;
}
static int bsd_identity(pid_t pid,pid_t wanted_parent,pid_t wanted_pgid) {
    struct proc_bsdinfo info;
    int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof info);
    return n==(int)sizeof info && (pid_t)info.pbi_pid==pid &&
           (pid_t)info.pbi_ppid==wanted_parent &&
           (pid_t)info.pbi_pgid==wanted_pgid;
}
static int child_reap(Child *p,long long deadline) {
    if(p->pid<=0 || p->reaped)return p->reaped;
    while(remaining(deadline)>0) {
        int raw=0;
        pid_t n=waitpid(p->pid,&raw,WNOHANG);
        if(n==p->pid){p->reaped=1;p->raw=raw;return 1;}
        if(n<0 && errno==EINTR)continue;
        if(n<0 && errno==ECHILD)return 0; /* identity no longer waitable */
        if(n<0)return 0;
        pause_10ms();
    }
    return 0;
}
static void child_release(Child *p) {
    close_fd(&p->input);
    close_fd(&p->output);
}
/* No direct-child kill fallback: cleanly close gates, bounded wait, fail closed.
 * Both children have an independent 8-second synthetic hard expiry.
 */
static int spawn_role(const char *binary,const char *root,int dir,
                      const char *role,int set_pgroup,pid_t newgroup,
                      Child *out) {
    int in[2]={-1,-1},outpipe[2]={-1,-1};
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int made_fa=0,made_attr=0,success=0;
    if(!private_pipe(in) || !private_pipe(outpipe))goto finish;
    if(posix_spawn_file_actions_init(&fa))goto finish;
    made_fa=1;
    if(posix_spawn_file_actions_addfchdir_np(&fa,dir) ||
       posix_spawn_file_actions_adddup2(&fa,in[0],STDIN_FILENO) ||
       posix_spawn_file_actions_adddup2(&fa,outpipe[1],STDOUT_FILENO) ||
       posix_spawn_file_actions_addclose(&fa,in[0]) ||
       posix_spawn_file_actions_addclose(&fa,in[1]) ||
       posix_spawn_file_actions_addclose(&fa,outpipe[0]) ||
       posix_spawn_file_actions_addclose(&fa,outpipe[1]) ||
       posix_spawn_file_actions_addopen(&fa,STDERR_FILENO,
                                       "/dev/null",O_WRONLY,0))goto finish;
    if(posix_spawnattr_init(&attr))goto finish;
    made_attr=1;
    sigset_t defaults,mask;
    if(sigemptyset(&defaults) || sigaddset(&defaults,SIGTERM) ||
       sigaddset(&defaults,SIGPIPE) || sigemptyset(&mask) ||
       posix_spawnattr_setsigdefault(&attr,&defaults) ||
       posix_spawnattr_setsigmask(&attr,&mask))goto finish;
    short flags=POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK;
    if(set_pgroup) {
        if(posix_spawnattr_setpgroup(&attr,newgroup))goto finish;
        flags|=POSIX_SPAWN_SETPGROUP;
    }
    if(posix_spawnattr_setflags(&attr,flags))goto finish;
    char *const argv[]={(char*)binary,(char*)role,(char*)root,NULL};
    int err=posix_spawn(&out->pid,binary,&fa,&attr,argv,environ);
    if(err){errno=err;out->pid=-1;goto finish;}
    success=1;
    out->input=in[1];in[1]=-1;
    out->output=outpipe[0];outpipe[0]=-1;
finish:
    if(made_attr)posix_spawnattr_destroy(&attr);
    if(made_fa)posix_spawn_file_actions_destroy(&fa);
    close_fd(&in[0]);close_fd(&in[1]);
    close_fd(&outpipe[0]);close_fd(&outpipe[1]);
    return success;
}
static int started_in_root(int dir) {
    struct stat st;
    return fstatat(dir,"C3B_WORK_STARTED",&st,AT_SYMLINK_NOFOLLOW)==0 &&
           S_ISREG(st.st_mode) && st.st_nlink==1 && st.st_uid==geteuid();
}
static int anchor_role(void) {
    alarm(8);
    if(getpgid(0)!=getpid() || !send_gate(STDOUT_FILENO,'A'))return 41;
    char ch=0;
    if(!receive_gate(STDIN_FILENO,&ch,now_ms()+6500))return 42;
    return ch=='Q'?0:43;
}
static int worker_role(const char *root) {
    alarm(8);
    WorkerReady ready={.magic=READY_MAGIC,.pid=getpid(),.ppid=getppid(),
                       .pgid=getpgid(0),.sid=getsid(0)};
    if(ready.ppid<=0 || ready.pgid<=0 || ready.sid<=0 ||
       !write_once(STDOUT_FILENO,&ready,sizeof ready))return 42;
    char gate=0;
    if(!receive_gate(STDIN_FILENO,&gate,now_ms()+6500) || gate!='G')return 44;
    /* Only code beyond this point represents synthetic workload execution. */
    int dir=-1;
    char binary[4096];
    if(snprintf(binary,sizeof binary,"%s/c3_candidate_b_native",root)<0 ||
       !private_root(root,binary,&dir))return 45;
    int marker=openat(dir,"C3B_WORK_STARTED",
                      O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(marker<0){close(dir);return 45;}
    int ok=write_once(marker,"yes",3);
    close(marker);close(dir);
    return ok?23:45;
}
static int controller_role(const char *root,const char *binary,int dir) {
    alarm(8);
    Setup set;
    long long deadline=now_ms()+6200;
    if(!wait_read(STDIN_FILENO,&set,sizeof set,deadline) ||
       set.magic!=SETUP_MAGIC || set.anchor<=0 || set.sid<=0 ||
       (set.mode!=M_POSITIVE && set.mode!=M_SPAWN_MISSING &&
        set.mode!=M_CROSS_SESSION && set.mode!=M_GATE_DENIED))
        return 51;
    if(set.mode==M_CROSS_SESSION) {
        if(setsid()<0 || getsid(0)==set.sid)return 52;
    }
    Proposal p={.magic=PROPOSAL_MAGIC,.seq=1,.controller=getpid(),
                .ctrl_pgid=getpgid(0),.ctrl_sid=getsid(0)};
    Child worker={.pid=-1,.input=-1,.output=-1};
    p.attempted=1;
    int spawned=spawn_role(binary,root,dir,"__worker",1,set.anchor,&worker);
    p.started=spawned?1:0;
    p.failure=spawned?0:1;
    if(spawned) {
        WorkerReady w;
        if(!wait_read(worker.output,&w,sizeof w,deadline) ||
           w.magic!=READY_MAGIC || w.pid!=worker.pid ||
           w.ppid!=getpid() || w.pgid!=getpgid(worker.pid) ||
           w.sid!=getsid(worker.pid)) {
            /* Keep worker gated and report a malformed proposal: Owner must deny. */
            p.failure=1;
        } else {
            p.worker=w.pid;
            p.reported_parent=w.ppid;
            p.worker_pgid=w.pgid;
            p.worker_sid=w.sid;
            if(set.mode==M_GATE_DENIED)
                p.reported_parent=0; /* Deliberate, fixed test-only misreport. */
        }
    }
    int stage_ok=write_once(STDOUT_FILENO,&p,sizeof p);
    char owner_grant=0;
    if(!stage_ok ||
       !receive_gate(STDIN_FILENO,&owner_grant,deadline))owner_grant='N';
    int open=(spawned && owner_grant=='G' && set.mode==M_POSITIVE);
    if(spawned) {
        if(!send_gate(worker.input,open?'G':'N'))open=0;
        close_fd(&worker.input);
    }
    Final f={.magic=FINAL_MAGIC,.seq=2,.waited=0,.status=0,
             .gate_opened=open,.worker=spawned?worker.pid:-1};
    int finished=1;
    if(spawned) {
        if(child_reap(&worker,deadline)) {
            f.waited=1;
            f.status=worker.raw;
        } else finished=0;
    }
    child_release(&worker);
    if(!write_once(STDOUT_FILENO,&f,sizeof f))finished=0;
    return finished?0:53;
}
static int owner_mode(const char *mode) {
    if(!strcmp(mode,"join-positive"))return M_POSITIVE;
    if(!strcmp(mode,"owner-reject-missing"))return M_OWNER_MISSING;
    if(!strcmp(mode,"join-nonexistent"))return M_SPAWN_MISSING;
    if(!strcmp(mode,"join-cross-session"))return M_CROSS_SESSION;
    if(!strcmp(mode,"gate-denied"))return M_GATE_DENIED;
    return 0;
}
static int owner_role(const char *mode,const char *root,
                      const char *binary,int dir) {
    int choice=owner_mode(mode),good=0;
    long long deadline=now_ms()+5300;
    Child anchor={.pid=-1,.input=-1,.output=-1};
    Child ctrl={.pid=-1,.input=-1,.output=-1};
    Observed o={0};
    const char *reason="spawn_anchor";
    pid_t own_sid=getsid(0);
    if(!choice || own_sid<=0 || !waitable_signals())return fail("startup");
    if(!spawn_role(binary,root,dir,"__anchor",1,0,&anchor))goto done;
    char ready=0;
    reason="anchor_ready";
    if(!receive_gate(anchor.output,&ready,deadline) || ready!='A' ||
       getpgid(anchor.pid)!=anchor.pid ||
       getsid(anchor.pid)!=own_sid ||
       !bsd_identity(anchor.pid,getpid(),anchor.pid))goto done;
    o.anchor_held=1;
    if(choice==M_OWNER_MISSING || choice==M_SPAWN_MISSING) {
        reason="anchor_retire";
        if(!send_gate(anchor.input,'Q') ||
           !child_reap(&anchor,deadline) ||
           !WIFEXITED(anchor.raw) || WEXITSTATUS(anchor.raw)!=0)
            goto done;
        errno=0;
        if(getpgid(anchor.pid)!=-1 || errno!=ESRCH)goto done;
        o.anchor_held=0;
        if(choice==M_OWNER_MISSING) {
            /* Distinct case: Owner refuses BEFORE any Controller/Worker spawn. */
            good=1;goto done;
        }
    }
    reason="spawn_controller";
    /* Cross SID: Controller inherits Owner PGID, then actually calls setsid().
       Normal mode: controller is its own group leader in the SAME session. */
    int create_own_group=choice!=M_CROSS_SESSION;
    if(!spawn_role(binary,root,dir,"__controller",create_own_group,0,&ctrl))
        goto done;
    Setup setup={.magic=SETUP_MAGIC,.mode=choice,.anchor=anchor.pid,
                 .sid=own_sid};
    reason="send_setup";
    if(!write_once(ctrl.input,&setup,sizeof setup))goto done;
    Proposal p;
    reason="controller_proposal";
    if(!wait_read(ctrl.output,&p,sizeof p,deadline) ||
       p.magic!=PROPOSAL_MAGIC || p.seq!=1 ||
       p.controller!=ctrl.pid)goto done;
    o.controller_outside=getpgid(ctrl.pid)!=anchor.pid;
    pid_t actual_sid=getsid(ctrl.pid);
    o.sid_distinct=actual_sid>0 && actual_sid!=own_sid;
    o.spawn_attempted=p.attempted;
    o.worker_spawned=p.started;
    if(p.ctrl_sid!=actual_sid || p.ctrl_pgid!=getpgid(ctrl.pid))
        goto done;
    reason="identity_validation";
    int anchor_ok=choice!=M_SPAWN_MISSING &&
           anchor.pid>0 && !anchor.reaped &&
           getpgid(anchor.pid)==anchor.pid &&
           getsid(anchor.pid)==own_sid &&
           bsd_identity(anchor.pid,getpid(),anchor.pid);
    if(!anchor_ok)o.anchor_held=0;
    int report_matches=0;
    if(p.started && p.worker>0) {
        pid_t kpgid=getpgid(p.worker),ksid=getsid(p.worker);
        /* Kernel PPID from libproc rather than trusting the child's message. */
        int real_parent=bsd_identity(p.worker,ctrl.pid,anchor.pid);
        o.parentage_verified=real_parent &&
             kpgid==anchor.pid && ksid>0;
        report_matches=p.reported_parent==ctrl.pid;
        o.join_verified=real_parent && kpgid==anchor.pid &&
                        ksid==own_sid && p.worker_pgid==kpgid &&
                        p.worker_sid==ksid;
    }
    o.owner_granted=choice==M_POSITIVE && anchor_ok &&
         o.controller_outside && !o.sid_distinct &&
         o.join_verified && o.parentage_verified && report_matches &&
         o.spawn_attempted && o.worker_spawned && !p.failure;
    /* Only Owner grants. No other branch may open worker-gate. */
    char grant=o.owner_granted?'G':'N';
    reason="owner-grant";
    if(!send_gate(ctrl.input,grant))goto done;
    Final final;
    reason="controller_final";
    if(!wait_read(ctrl.output,&final,sizeof final,deadline) ||
       final.magic!=FINAL_MAGIC || final.seq!=2 ||
       (p.started && final.worker!=p.worker))goto done;
    o.gate_opened=final.gate_opened;
    o.controller_waited=final.waited;
    if(o.controller_waited && !WIFEXITED(final.status))goto done;
    int expected_worker=choice==M_POSITIVE?23:44;
    if(o.controller_waited &&
       WEXITSTATUS(final.status)!=expected_worker)goto done;
    o.workload_started=started_in_root(dir);
    if(choice==M_POSITIVE) {
        good=anchor_ok && o.controller_outside && !o.sid_distinct &&
             o.spawn_attempted && o.worker_spawned &&
             o.join_verified && o.parentage_verified &&
             o.owner_granted && o.gate_opened && o.workload_started &&
             o.controller_waited;
    } else if(choice==M_SPAWN_MISSING || choice==M_CROSS_SESSION) {
        good=o.controller_outside && o.spawn_attempted &&
             !o.worker_spawned && !o.join_verified &&
             !o.owner_granted && !o.gate_opened &&
             !o.workload_started && !o.controller_waited &&
             ((choice==M_CROSS_SESSION && o.sid_distinct && anchor_ok) ||
              (choice==M_SPAWN_MISSING && !o.sid_distinct && !anchor_ok));
    } else if(choice==M_GATE_DENIED) {
        /* Kernel parentage is valid, but Controller's *reported* parent is
           deliberately invalid. Independent Owner MUST NOT release gate. */
        good=anchor_ok && o.controller_outside && !o.sid_distinct &&
             o.spawn_attempted && o.worker_spawned && o.join_verified &&
             o.parentage_verified && !report_matches && !o.owner_granted &&
             !o.gate_opened && !o.workload_started && o.controller_waited;
    }
    reason="typed_outcome";
done:
    /* Always close Controller stdin then Anchor gate. NO group signal,
       no direct PID kill and no production process supervision. */
    close_fd(&ctrl.input);
    if(anchor.pid>0 && !anchor.reaped)
        (void)send_gate(anchor.input,'Q');
    close_fd(&anchor.input);
    int c_reaped=ctrl.pid<=0 || child_reap(&ctrl,deadline);
    int a_reaped=anchor.pid<=0 || child_reap(&anchor,deadline);
    o.cleanup_complete=c_reaped && a_reaped;
    if(ctrl.pid>0 && (!ctrl.reaped || !WIFEXITED(ctrl.raw) ||
                      WEXITSTATUS(ctrl.raw)!=0))o.cleanup_complete=0;
    if(anchor.pid>0 && (!anchor.reaped || !WIFEXITED(anchor.raw) ||
                        WEXITSTATUS(anchor.raw)!=0))o.cleanup_complete=0;
    child_release(&anchor);child_release(&ctrl);
    if(!good || !o.cleanup_complete)return fail(reason);
    printf("C3B_RESULT mode=%s anchor_held=%d controller_outside=%d "
           "sid_distinct=%d spawn_attempted=%d worker_spawned=%d "
           "join_verified=%d parentage_verified=%d owner_granted=%d "
           "gate_opened=%d workload_started=%d controller_waited=%d "
           "cleanup_complete=%d reuse_proven=0 g2_qualified=0\n",
           mode,o.anchor_held,o.controller_outside,o.sid_distinct,
           o.spawn_attempted,o.worker_spawned,o.join_verified,
           o.parentage_verified,o.owner_granted,o.gate_opened,
           o.workload_started,o.controller_waited,o.cleanup_complete);
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=3)return fail("args");
    const char *role=argv[1], *root=argv[2];
    int dir=-1;
    if(!private_root(root,argv[0],&dir))return fail("private_root");
    if(!strcmp(role,"__anchor")) {
        close(dir);return anchor_role();
    }
    if(!strcmp(role,"__controller")) {
        int result=controller_role(root,argv[0],dir);
        close(dir);return result;
    }
    if(!strcmp(role,"__worker")) {
        close(dir);return worker_role(root);
    }
    int result=owner_role(role,root,argv[0],dir);
    close(dir);return result;
}
#endif
