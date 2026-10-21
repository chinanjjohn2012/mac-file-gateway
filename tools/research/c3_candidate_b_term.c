/*
 * Phase2-Lite Candidate B B02-R2 — Darwin ARM64 synthetic TERM ONLY.
 *
 * Private process tree:
 *   Owner -> held Anchor PG leader
 *         -> external Controller PG leader -> Worker in Anchor's PGID.
 * Owner is the sole group signaler and only Anchor/Controller waiter.
 * Controller is Worker's only legitimate waitpid parent.
 *
 * Fixed test mode/owned 0700 root only; no arbitrary command or existing PGID.
 * No forced group KILL; no G2 qualification. This is NOT ExecSupervisor.
 */
#ifndef __APPLE__
#include <stdio.h>
int main(void) { puts("C3B02_NOT_RUN_NON_DARWIN"); return 77; }
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

/* An ownership-gate deletion may only be studied with a guaranteed
 * no-signal stub. No stale numeric PGID is ever sent TERM in T05. */
#if defined(C3B02_MUT_SKIP_ANCHOR_CHECK) && !defined(C3B02_TEST_STALE_KILL_STUB)
#error "An Anchor gate bypass is only allowed with the no-signal stub"
#endif

extern char **environ;
enum { POSITIVE=1, NO_SIGDEF=2, NO_SIGMASK=3, CTRL_REGRESSION=4,
       ANCHOR_LOST=5, DEADLINE=6, CANARY=7, RESULT_LOST=8 };
enum { MAGIC_CTRL=0x43334261, MAGIC_SETUP=0x43334262,
       MAGIC_WORKER=0x43334263, MAGIC_PROPOSAL=0x43334264,
       MAGIC_ARMED=0x43334265, MAGIC_FINAL=0x43334266 };
typedef struct {
    int anchor_held, controller_group_leader, controller_inherited_ignore,
        controller_inherited_block, worker_spawned, worker_default_term,
        worker_unblocked_term, worker_armed, term_attempts, term_succeeded,
        controller_waited, worker_observed_term, admission_cutoff_expired,
        outer_live_at_refusal, gate_opened, cleanup_complete,
        canary_survived, worker_result_unknown, result_lost_after_wait,
        owner_children_reaped, anchor_loss_gate_checked,
        after_loss_attempts, owner_fds_closed, controller_worker_fds_closed;
} Observation;
typedef struct { pid_t pid; int input,output,reaped,status; } Child;
typedef struct { int magic,seq; pid_t pid,pgid,sid; } ControllerReady;
typedef struct {
    int magic,mode; pid_t anchor,owner_sid;
    long long outer_deadline,term_admission_cutoff;
} Setup;
typedef struct {
    int magic,default_term,unblocked_term;
    pid_t pid,ppid,pgid,sid;
} WorkerReady;
typedef struct {
    int magic,seq,controller_inherited_ignore,controller_inherited_block;
    int started,failed,worker_default_term,worker_unblocked_term;
    pid_t worker,worker_ppid,worker_pgid,worker_sid;
} Proposal;
typedef struct { int magic,seq; pid_t worker; int worker_armed; } Armed;
typedef struct {
    int magic,seq,waited,raw_status,gate_opened,worker_armed,
        worker_fds_closed;
    pid_t worker;
} Final;
static long long clock_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (long long)t.tv_sec*1000 + t.tv_nsec/1000000;
}
static long remaining(long long end) {
    long long v=end-clock_ms();
    return v<=0?0:v>5000?5000:(long)v;
}
static int term_admitted(long long now,long long cutoff,long long outer) {
    return now>=0 && now<cutoff && now<outer && cutoff<outer;
}
static void tiny_pause(void) {
    struct timespec t={.tv_sec=0,.tv_nsec=10000000L};
    while(nanosleep(&t,&t)<0 && errno==EINTR) {}
}
/* Do not retry a numeric FD after close() returns an error. */
static int managed_fd_close_ok=1;
static int inject_close_error_once=0;
static int close_fd(int *fd) {
    if(*fd<0)return 1;
    int v=*fd;*fd=-1;
    int ok=close(v)==0; /* Real close always runs before fault injection. */
    if(inject_close_error_once) {
        inject_close_error_once=0;errno=EIO;ok=0;
    }
    if(!ok)managed_fd_close_ok=0;
    return ok;
}
static int pipe_private(int fd[2]) {
    if(pipe(fd))return 0;
    if(fcntl(fd[0],F_SETFD,FD_CLOEXEC)<0 ||
       fcntl(fd[1],F_SETFD,FD_CLOEXEC)<0) {
        close(fd[0]);close(fd[1]);fd[0]=fd[1]=-1;return 0;
    }
    return 1;
}
static int read_exact(int fd,void *dst,size_t n,long long deadline) {
    unsigned char *p=(unsigned char*)dst;
    size_t off=0;
    while(off<n && remaining(deadline)>0) {
        struct pollfd item={.fd=fd,.events=POLLIN|POLLHUP};
        long wait=remaining(deadline);
        if(wait>100)wait=100;
        int r=poll(&item,1,(int)wait);
        if(r<0 && errno==EINTR)continue;
        if(r==0)continue;
        if(r<0)return 0;
        ssize_t got=read(fd,p+off,n-off);
        if(got<0 && errno==EINTR)continue;
        if(got<=0)return 0;
        off+=(size_t)got;
    }
    return off==n;
}
static int write_exact(int fd,const void *p,size_t n,long long deadline) {
    if(remaining(deadline)<=0)return 0;
    /* One writer, small frames well under PIPE_BUF; no stream mixing. */
    for(;;) {
        ssize_t wrote=write(fd,p,n);
        if(wrote<0 && errno==EINTR && remaining(deadline)>0)continue;
        return wrote==(ssize_t)n;
    }
}
static int send_char(int fd,char ch,long long until) {
    return write_exact(fd,&ch,1,until);
}
static int recv_char(int fd,char *ch,long long until) {
    return read_exact(fd,ch,1,until);
}
static int block_fail(const char *phase) {
    fprintf(stderr,"C3B02_BLOCK phase=%s\n",phase);
    return 70;
}
static int signal_setup(void) {
    struct sigaction sa,current;
    memset(&sa,0,sizeof sa);
    sa.sa_handler=SIG_DFL;
    if(sigemptyset(&sa.sa_mask) || sigaction(SIGCHLD,&sa,NULL) ||
       sigaction(SIGCHLD,NULL,&current) ||
       current.sa_handler!=SIG_DFL ||
       (current.sa_flags&SA_NOCLDWAIT))return 0;
    sa.sa_handler=SIG_IGN;
    if(sigaction(SIGPIPE,&sa,NULL) ||
       sigaction(SIGPIPE,NULL,&current) ||
       current.sa_handler!=SIG_IGN)return 0;
    return 1;
}
static int root_owned(const char *root,const char *self,int *result) {
    if(!root||root[0]!='/'||!self)return 0;
    const size_t n=strlen(root);
    if(strncmp(root,self,n) || strcmp(self+n,"/c3_candidate_b_term"))return 0;
    int dir=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return 0;
    struct stat st;
    if(fstat(dir,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||
       (st.st_mode&0077))goto bad;
    int f=openat(dir,"C3B02_TEST_MARKER",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(f<0)goto bad;
    char mark[16]={0};
    ssize_t got=read(f,mark,sizeof mark);
    int okay=(!fstat(f,&st)&&S_ISREG(st.st_mode)&&st.st_uid==geteuid()&&
              st.st_nlink==1&&got==9&&!memcmp(mark,"synthetic",9));
    if(!close_fd(&f))goto bad;
    if(!okay)goto bad;
    int exe=openat(dir,"c3_candidate_b_term",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(exe<0)goto bad;
    okay=(!fstat(exe,&st)&&S_ISREG(st.st_mode)&&st.st_uid==geteuid()&&
          st.st_nlink==1&&(st.st_mode&0111));
    if(!close_fd(&exe))goto bad;
    if(!okay)goto bad;
    *result=dir;return 1;
bad:
    (void)close_fd(&dir);return 0;
}
static int bsd_owned(pid_t pid,pid_t parent,pid_t pgid) {
    struct proc_bsdinfo info;
    int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof info);
    return n==(int)sizeof info && (pid_t)info.pbi_pid==pid &&
           (pid_t)info.pbi_ppid==parent && (pid_t)info.pbi_pgid==pgid;
}
static int wait_child(Child *child,long long until) {
    if(child->pid<=0||child->reaped)return child->reaped;
    while(remaining(until)>0) {
        int raw=0;
        pid_t r=waitpid(child->pid,&raw,WNOHANG);
        if(r==child->pid){child->reaped=1;child->status=raw;return 1;}
        if(r<0 && errno==EINTR)continue;
        if(r<0)return 0;
        tiny_pause();
    }
    return 0;
}
static int close_child(Child *p) {
    int in_ok=close_fd(&p->input);
    int out_ok=close_fd(&p->output);
    return in_ok && out_ok;
}
static int spawn_role(const char *self,const char *root,int dir,
                      const char *role,int separate,pid_t pgid,
                      int reset_term,int unblock_term,Child *child) {
    int inp[2]={-1,-1},outp[2]={-1,-1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int fa=0,attr=0,success=0;
    if(!pipe_private(inp)||!pipe_private(outp))goto done;
    if(posix_spawn_file_actions_init(&actions))goto done;
    fa=1;
    if(posix_spawn_file_actions_addfchdir_np(&actions,dir) ||
       posix_spawn_file_actions_adddup2(&actions,inp[0],STDIN_FILENO) ||
       posix_spawn_file_actions_adddup2(&actions,outp[1],STDOUT_FILENO) ||
       posix_spawn_file_actions_addclose(&actions,inp[0]) ||
       posix_spawn_file_actions_addclose(&actions,inp[1]) ||
       posix_spawn_file_actions_addclose(&actions,outp[0]) ||
       posix_spawn_file_actions_addclose(&actions,outp[1]) ||
       posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,
                                       "/dev/null",O_WRONLY,0))goto done;
    if(posix_spawnattr_init(&attributes))goto done;
    attr=1;
    sigset_t defs,mask;
    if(sigemptyset(&defs) || sigaddset(&defs,SIGPIPE) ||
       sigemptyset(&mask))goto done;
    if(reset_term && sigaddset(&defs,SIGTERM))goto done;
    if(posix_spawnattr_setsigdefault(&attributes,&defs))goto done;
    short flags=POSIX_SPAWN_SETSIGDEF;
    if(unblock_term) {
        if(posix_spawnattr_setsigmask(&attributes,&mask))goto done;
        flags|=POSIX_SPAWN_SETSIGMASK;
    }
    if(separate) {
        if(posix_spawnattr_setpgroup(&attributes,pgid))goto done;
        flags|=POSIX_SPAWN_SETPGROUP;
    }
    if(posix_spawnattr_setflags(&attributes,flags))goto done;
    char *const argv[]={(char*)self,(char*)role,(char*)root,NULL};
    int err=posix_spawn(&child->pid,self,&actions,&attributes,argv,environ);
    if(err){child->pid=-1;errno=err;goto done;}
    child->input=inp[1];inp[1]=-1;
    child->output=outp[0];outp[0]=-1;
    success=1;
done:
    if(attr)posix_spawnattr_destroy(&attributes);
    if(fa)posix_spawn_file_actions_destroy(&actions);
    close_fd(&inp[0]);close_fd(&inp[1]);
    close_fd(&outp[0]);close_fd(&outp[1]);
    return success;
}
static int signals_term_state(int *is_default,int *is_unblocked) {
    struct sigaction sa;
    sigset_t old;
    if(sigaction(SIGTERM,NULL,&sa) ||
       sigprocmask(SIG_SETMASK,NULL,&old))return 0;
    *is_default=sa.sa_handler==SIG_DFL;
    *is_unblocked=sigismember(&old,SIGTERM)==0;
    return 1;
}
static int set_ignore_term(void) {
    struct sigaction sa,current;
    memset(&sa,0,sizeof sa);
    sa.sa_handler=SIG_IGN;
    if(sigemptyset(&sa.sa_mask) ||
       sigaction(SIGTERM,&sa,NULL) ||
       sigaction(SIGTERM,NULL,&current) ||
       current.sa_handler!=SIG_IGN)return 0;
    return 1;
}
static int ctrl_adverse_term(int *ignore,int *blocked) {
    if(!set_ignore_term())return 0;
    sigset_t mask,check;
    if(sigemptyset(&mask)||sigaddset(&mask,SIGTERM) ||
       sigprocmask(SIG_BLOCK,&mask,NULL) ||
       sigprocmask(SIG_SETMASK,NULL,&check))return 0;
    struct sigaction sa;
    if(sigaction(SIGTERM,NULL,&sa))return 0;
    *ignore=sa.sa_handler==SIG_IGN;
    *blocked=sigismember(&check,SIGTERM)==1;
    return *ignore && *blocked;
}
static int anchor_role(void) {
    alarm(7);
    if(!signal_setup())return 41;
    if(!set_ignore_term() || getpgid(0)!=getpid())return 41;
    int dfl,unblocked;
    if(!signals_term_state(&dfl,&unblocked)||dfl)return 41;
    long long until=clock_ms()+6800;
    if(!send_char(STDOUT_FILENO,'A',until))return 42;
    char c=0;
    if(!recv_char(STDIN_FILENO,&c,until))return 0; /* cooperative EOF */
    return c=='Q'?0:43;
}
static int marker_present(int dir,const char *name) {
    struct stat st;
    return fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)==0 &&
           S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_uid==geteuid();
}
static int canary_role(void) {
    alarm(7);
    if(!signal_setup() || getpgid(0)!=getpid())return 61;
    int term_default=0,unblocked=0;
    if(!signals_term_state(&term_default,&unblocked) ||
       !term_default || !unblocked)return 61;
    const long long until=clock_ms()+6800;
    if(!send_char(STDOUT_FILENO,'C',until))return 62;
    char q=0;
    if(!recv_char(STDIN_FILENO,&q,until))return 0; /* cooperative EOF */
    return q=='Q'?0:63;
}
static int worker_role(int dir) {
    alarm(7);
    if(!signal_setup())return 45;
    WorkerReady w={.magic=MAGIC_WORKER,.pid=getpid(),.ppid=getppid(),
                   .pgid=getpgid(0),.sid=getsid(0)};
    if(w.ppid<=0||w.pgid<=0||w.sid<=0||
       !signals_term_state(&w.default_term,&w.unblocked_term) ||
       !write_exact(STDOUT_FILENO,&w,sizeof w,clock_ms()+6500))return 45;
    char gate=0;
    if(!recv_char(STDIN_FILENO,&gate,clock_ms()+6500)||gate!='G')return 44;
    int fd=openat(dir,"C3B02_WORK_ARMED",
                  O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(fd<0)return 45;
    int marked=write_exact(fd,"armed",5,clock_ms()+6000);
    if(!close_fd(&fd))marked=0;
    if(!marked || !send_char(STDOUT_FILENO,'A',clock_ms()+6500))return 45;
    /* Only a default/unblocked real SIGTERM should terminate this wait.
       In negative modes the Controller later sends cooperative 'Q'. */
    char q=0;
    if(!recv_char(STDIN_FILENO,&q,clock_ms()+6500))return 24;
    return q=='Q'?24:46;
}
static int controller_role(const char *self,const char *root,int dir) {
    alarm(7);
    if(!signal_setup())return 51; /* all pipe writes fail as EPIPE */
    long long initial=clock_ms()+6500;
    ControllerReady ready={.magic=MAGIC_CTRL,.seq=1,.pid=getpid(),
                           .pgid=getpgid(0),.sid=getsid(0)};
    if(!write_exact(STDOUT_FILENO,&ready,sizeof ready,initial))return 51;
    Setup setup;
    if(!read_exact(STDIN_FILENO,&setup,sizeof setup,initial))
        return managed_fd_close_ok?0:51; /* refused BEFORE Worker spawn */
    if(setup.magic!=MAGIC_SETUP || setup.anchor<=0 ||
       setup.owner_sid<=0 || setup.outer_deadline<=clock_ms() ||
       (setup.mode!=POSITIVE && setup.mode!=NO_SIGDEF &&
        setup.mode!=NO_SIGMASK && setup.mode!=DEADLINE &&
        setup.mode!=CANARY && setup.mode!=RESULT_LOST &&
        setup.mode!=ANCHOR_LOST))return 52;
    Proposal p={.magic=MAGIC_PROPOSAL,.seq=2};
    if(!ctrl_adverse_term(&p.controller_inherited_ignore,
                          &p.controller_inherited_block))return 53;
    Child w={.pid=-1,.input=-1,.output=-1};
    int reset_term=setup.mode!=NO_SIGDEF;
    int unblock_term=setup.mode!=NO_SIGMASK;
#ifdef C3B02_MUT_OMIT_SIGDEF
    if(setup.mode==POSITIVE)reset_term=0;
#endif
#ifdef C3B02_MUT_OMIT_SIGMASK
    if(setup.mode==POSITIVE)unblock_term=0;
#endif
    p.started=spawn_role(self,root,dir,"__worker",1,setup.anchor,
                         reset_term,unblock_term,&w);
    p.failed=!p.started;
    int valid=0;
    if(p.started) {
        WorkerReady wr;
        valid=read_exact(w.output,&wr,sizeof wr,setup.outer_deadline) &&
              wr.magic==MAGIC_WORKER && wr.pid==w.pid &&
              wr.ppid==getpid() && wr.pgid==setup.anchor &&
              wr.sid==setup.owner_sid &&
              getpgid(w.pid)==setup.anchor &&
              getsid(w.pid)==setup.owner_sid &&
              bsd_owned(w.pid,getpid(),setup.anchor);
        if(valid) {
            p.worker=wr.pid;p.worker_ppid=wr.ppid;
            p.worker_pgid=wr.pgid;p.worker_sid=wr.sid;
            p.worker_default_term=wr.default_term;
            p.worker_unblocked_term=wr.unblocked_term;
        } else p.failed=1;
    }
    if(!write_exact(STDOUT_FILENO,&p,sizeof p,setup.outer_deadline))goto bad;
    char grant='N';
    if(!recv_char(STDIN_FILENO,&grant,setup.outer_deadline))grant='N';
    int opened=valid && grant=='G';
    if(p.started) {
        if(!send_char(w.input,opened?'G':'N',setup.outer_deadline))
            opened=0;
    }
    Armed armed={.magic=MAGIC_ARMED,.seq=3,
                 .worker=w.pid,.worker_armed=0};
    if(opened) {
        char arm=0;
        if(recv_char(w.output,&arm,setup.outer_deadline) &&
           arm=='A' && getpgid(w.pid)==setup.anchor &&
           marker_present(dir,"C3B02_WORK_ARMED"))armed.worker_armed=1;
    }
    if(!write_exact(STDOUT_FILENO,&armed,sizeof armed,setup.outer_deadline))
        goto bad;
    char action='N';
    if(!recv_char(STDIN_FILENO,&action,setup.outer_deadline))action='N';
    if(action!='T' || (setup.mode!=POSITIVE &&
                       setup.mode!=CANARY && setup.mode!=RESULT_LOST)) {
        /* T02/T03: TERM may have been sent but must NOT count as signal exit.
           T06: no TERM attempted; cooperative closure within cleanup reserve. */
        if(action=='T' && (setup.mode==NO_SIGDEF ||
                            setup.mode==NO_SIGMASK)) {
            int raw=0;
            pid_t r=waitpid(w.pid,&raw,WNOHANG);
            if(r!=0)goto bad; /* cannot fake "survived TERM" */
        }
        if(w.pid>0)(void)send_char(w.input,'Q',setup.outer_deadline);
    }
    int worker_input_ok=close_fd(&w.input);
    Final f={.magic=MAGIC_FINAL,.seq=4,.worker=w.pid,
             .gate_opened=opened,.worker_armed=armed.worker_armed};
    if(w.pid>0 && wait_child(&w,setup.outer_deadline)){
        f.waited=1;f.raw_status=w.status;
    }
#ifdef C3B02_FAULT_CONTROLLER_CLOSE
    if(setup.mode==POSITIVE && w.output>=0)
        inject_close_error_once=1; /* AFTER Worker waitpid */
#endif
    int worker_other_fd_ok=close_child(&w);
    f.worker_fds_closed=worker_input_ok && worker_other_fd_ok &&
                         managed_fd_close_ok;
    if(setup.mode==RESULT_LOST) {
        /* Controlled P3 fault: AFTER legitimate direct Worker waitpid,
           BEFORE transmitting the status. This marker is research-only
           fault timing, NEVER a substitute for a trusted FINAL/result. */
        if(!f.waited || !WIFSIGNALED(f.raw_status) ||
           WTERMSIG(f.raw_status)!=SIGTERM)return 55;
        int audit=openat(dir,"C3B02_AFTER_WAIT_BEFORE_FINAL",
                         O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if(audit<0)return 55;
        int okay=write_exact(audit,"waited",6,setup.outer_deadline);
        if(!close_fd(&audit))okay=0;
        return okay && f.worker_fds_closed?0:55;
        /* no FINAL frame; Owner must report UNKNOWN */
    }
    if(!write_exact(STDOUT_FILENO,&f,sizeof f,setup.outer_deadline))
        return 54;
    return f.waited && f.worker_fds_closed ? 0 : 55;
bad:
    close_fd(&w.input);
    if(w.pid>0)(void)wait_child(&w,setup.outer_deadline);
    close_child(&w);
    return 56;
}
static int mode_number(const char *v) {
    if(!strcmp(v,"term-positive"))return POSITIVE;
    if(!strcmp(v,"missing-sigdef"))return NO_SIGDEF;
    if(!strcmp(v,"missing-sigmask"))return NO_SIGMASK;
    if(!strcmp(v,"controller-group-regression"))return CTRL_REGRESSION;
    if(!strcmp(v,"anchor-lost-before-term"))return ANCHOR_LOST;
    if(!strcmp(v,"deadline-before-term"))return DEADLINE;
    if(!strcmp(v,"canary-isolation"))return CANARY;
    if(!strcmp(v,"controller-result-lost"))return RESULT_LOST;
    return 0;
}
static int live_anchor(Child *a,pid_t owner_pid,pid_t sid) {
    return a->pid>0&&!a->reaped &&
           getpgid(a->pid)==a->pid && getsid(a->pid)==sid &&
           bsd_owned(a->pid,owner_pid,a->pid);
}
/* A user-space identity guard, not a kernel-atomic PGID capability. */
static int send_term_to_owned_group(Child *anchor,Child *controller,
                                    pid_t owner_pid,pid_t sid,
                                    long long term_admission_cutoff,
                                    long long outer_deadline,
                                    Observation *o,int mode) {
    /* T05 must actually enter this admission function, not skip in caller. */
    if(mode==ANCHOR_LOST)o->anchor_loss_gate_checked=1;
    int anchor_ok=live_anchor(anchor,owner_pid,sid);
#ifdef C3B02_MUT_SKIP_ANCHOR_CHECK
    if(mode==ANCHOR_LOST)anchor_ok=1; /* safety mutation only */
#endif
    if(!anchor_ok || controller->pid<=0 || controller->reaped ||
       getpgid(controller->pid)!=controller->pid ||
       getsid(controller->pid)!=sid ||
       !bsd_owned(controller->pid,owner_pid,controller->pid))return 0;
    if(!term_admitted(clock_ms(),term_admission_cutoff,outer_deadline))
        return 0;
    ++o->term_attempts; /* before a potential native syscall */
    if(mode==ANCHOR_LOST) {
        /* Test-only interception: a stale numeric PGID is NEVER signaled.
           This captures an authorization regression even on ESRCH. */
        ++o->after_loss_attempts;
        errno=ESRCH;
        return 0;
    }
    if(kill(-anchor->pid,SIGTERM)!=0)return 0;
    o->term_succeeded=1;
    return 1;
}
static int wait_until_cutoff(long long cutoff,long long outer_deadline) {
    /* Used only AFTER actual ARMED event: scheduling the admission-negative. */
    while(clock_ms()<cutoff && remaining(outer_deadline)>0) {
        long m=cutoff-clock_ms();
        if(m>80)m=80;
        if(m<=0)break;
        if(poll(NULL,0,(int)m)<0 && errno!=EINTR)return 0;
    }
    return clock_ms()>=cutoff && clock_ms()<outer_deadline;
}
static int owner_role(const char *mode,const char *self,
                      const char *root,int *owner_dir) {
    (void)root;
    int dir=*owner_dir; /* close this owned directory FD before output */
    int which=mode_number(mode),accepted=0;
    Observation o={0};
    Child anchor={.pid=-1,.input=-1,.output=-1};
    Child controller={.pid=-1,.input=-1,.output=-1};
    Child canary={.pid=-1,.input=-1,.output=-1};
    const long long outer_deadline=clock_ms()+8000;
    const long long cleanup_reserve_ms=2600;
    const long long term_admission_cutoff=outer_deadline-cleanup_reserve_ms;
    const pid_t owner=getpid(),sid=getsid(0);
    const char *reason="owner_init";
    if(!which || sid<=0 || !signal_setup() ||
       cleanup_reserve_ms<=0 || term_admission_cutoff>=outer_deadline)
        return block_fail(reason);
    reason="spawn_anchor";
    if(!spawn_role(self,root,dir,"__anchor",1,0,1,1,&anchor))goto done;
    char ra=0;
    reason="anchor_ready";
    if(!recv_char(anchor.output,&ra,outer_deadline) || ra!='A' ||
       !live_anchor(&anchor,owner,sid))goto done;
    o.anchor_held=1;
    if(which==CANARY) {
        reason="spawn_canary";
        if(!spawn_role(self,root,dir,"__canary",1,0,1,1,&canary))
            goto done;
        char response=0;
        reason="canary_ready";
        if(!recv_char(canary.output,&response,outer_deadline) ||
           response!='C' || canary.pid<=0 ||
           getpgid(canary.pid)!=canary.pid ||
           getsid(canary.pid)!=sid ||
           !bsd_owned(canary.pid,owner,canary.pid) ||
           canary.pid==anchor.pid)goto done;
    }
    reason="spawn_controller";
    int group=which!=CTRL_REGRESSION;
#ifdef C3B02_MUT_CTRL_GROUP
    if(which==POSITIVE)group=0;
#endif
    if(!spawn_role(self,root,dir,"__controller",group,0,1,1,&controller))
        goto done;
    ControllerReady cr;
    reason="controller_ready";
    if(!read_exact(controller.output,&cr,sizeof cr,outer_deadline) ||
       cr.magic!=MAGIC_CTRL || cr.seq!=1 ||
       cr.pid!=controller.pid)goto done;
    /* P3 from B-01: require Controller's OWN group identity, not merely
       "Controller is outside Anchor group". */
    o.controller_group_leader=(getpgid(controller.pid)==controller.pid &&
       getsid(controller.pid)==sid &&
       bsd_owned(controller.pid,owner,controller.pid) &&
       cr.pgid==controller.pid && cr.sid==sid);
    if(!o.controller_group_leader) {
        reason="controller_group";
        accepted=which==CTRL_REGRESSION;
        goto done; /* before setup or Worker spawn, zero TERM attempts */
    }
    if(which==CTRL_REGRESSION)goto done; /* mutation accidentally passed */
    Setup setup={.magic=MAGIC_SETUP,.mode=which,.anchor=anchor.pid,
                 .owner_sid=sid,.outer_deadline=outer_deadline,
                 .term_admission_cutoff=term_admission_cutoff};
    reason="setup";
    if(!write_exact(controller.input,&setup,sizeof setup,outer_deadline))
        goto done;
    Proposal p;
    reason="worker_proposal";
    if(!read_exact(controller.output,&p,sizeof p,outer_deadline) ||
       p.magic!=MAGIC_PROPOSAL || p.seq!=2 ||
       !p.started || p.failed || p.worker<=0)goto done;
    o.controller_inherited_ignore=p.controller_inherited_ignore;
    o.controller_inherited_block=p.controller_inherited_block;
    o.worker_spawned=p.started;
    o.worker_default_term=p.worker_default_term;
    o.worker_unblocked_term=p.worker_unblocked_term;
    int worker_identity=live_anchor(&anchor,owner,sid) &&
       getpgid(p.worker)==anchor.pid &&
       getsid(p.worker)==sid &&
       bsd_owned(p.worker,controller.pid,anchor.pid) &&
       p.worker_ppid==controller.pid && p.worker_pgid==anchor.pid &&
       p.worker_sid==sid;
    int adverse=o.controller_inherited_ignore &&
                o.controller_inherited_block;
    int eligible=worker_identity && adverse && o.controller_group_leader;
    /* Fixed-mode negative controls are not a generic production bypass:
       they explicitly require proven abnormal inherited Worker SIGTERM. */
    if(which==POSITIVE || which==DEADLINE ||
       which==CANARY || which==RESULT_LOST || which==ANCHOR_LOST)
        eligible=eligible&&o.worker_default_term&&o.worker_unblocked_term;
    else if(which==NO_SIGDEF)
        eligible=eligible&&!o.worker_default_term&&o.worker_unblocked_term;
    else if(which==NO_SIGMASK)
        eligible=eligible&&o.worker_default_term&&!o.worker_unblocked_term;
    if(!eligible){reason="worker_signal_ineligible";goto done;}
    reason="worker_grant";
    if(!send_char(controller.input,'G',outer_deadline))goto done;
    o.gate_opened=1;
    Armed arm;
    reason="worker_armed";
    if(!read_exact(controller.output,&arm,sizeof arm,outer_deadline) ||
       arm.magic!=MAGIC_ARMED || arm.seq!=3 ||
       arm.worker!=p.worker || !arm.worker_armed ||
       !marker_present(dir,"C3B02_WORK_ARMED"))goto done;
    o.worker_armed=1;
    reason="term_admission";
    if(!live_anchor(&anchor,owner,sid) ||
       getpgid(p.worker)!=anchor.pid ||
       getsid(p.worker)!=sid ||
       !bsd_owned(p.worker,controller.pid,anchor.pid))
        goto done;
    int action_success=0;
    if(which==ANCHOR_LOST) {
        /* Real Worker PGID join + real ARMED event preceded this point.
           Retire and waitpid the held Anchor without retiring Worker. */
        reason="anchor_retire_after_worker_armed";
        if(!send_char(anchor.input,'Q',outer_deadline) ||
           !wait_child(&anchor,outer_deadline) ||
           !WIFEXITED(anchor.status) || WEXITSTATUS(anchor.status)!=0)
            goto done;
        errno=0;
        if(getpgid(anchor.pid)!=-1 || errno!=ESRCH)goto done;
        o.anchor_held=0;
        reason="stale_anchor_signal_admission";
        if(send_term_to_owned_group(&anchor,&controller,owner,sid,
             term_admission_cutoff,outer_deadline,&o,which))
            goto done; /* no real group TERM in T05 */
        if(!send_char(controller.input,'D',outer_deadline))goto done;
        action_success=1;
    } else if(which==DEADLINE) {
        if(!wait_until_cutoff(term_admission_cutoff,outer_deadline))
            goto done;
        o.admission_cutoff_expired=clock_ms()>=term_admission_cutoff;
        o.outer_live_at_refusal=clock_ms()<outer_deadline;
        if(!o.admission_cutoff_expired||!o.outer_live_at_refusal)
            goto done;
        /* Must traverse the actual helper admission gate, not simply skip. */
        if(send_term_to_owned_group(&anchor,&controller,owner,sid,
             term_admission_cutoff,outer_deadline,&o,which))goto done;
        if(o.term_attempts!=0 || o.term_succeeded)goto done;
        reason="deadline_cleanup";
        if(!send_char(controller.input,'D',outer_deadline))goto done;
        action_success=1;
    } else {
        if(!send_term_to_owned_group(&anchor,&controller,owner,sid,
             term_admission_cutoff,outer_deadline,&o,which))goto done;
        reason="term_dispatched";
        if(!send_char(controller.input,'T',outer_deadline))goto done;
        action_success=1;
    }
    Final f;
    reason="controller_wait";
    if(!action_success)goto done;
    int final_received=read_exact(controller.output,&f,sizeof f,
                                  outer_deadline);
    if(which==RESULT_LOST) {
        /* This fault occurs after Controller's real Worker wait.
           An audit marker helps validate the synthetic fault's TIMING,
           but cannot supply a Worker exit status to Owner. */
        if(final_received)goto done;
        o.worker_result_unknown=1;
        o.result_lost_after_wait=marker_present(
            dir,"C3B02_AFTER_WAIT_BEFORE_FINAL");
        accepted=o.result_lost_after_wait && o.term_attempts==1 &&
                 o.term_succeeded && o.worker_armed &&
                 o.gate_opened && o.worker_spawned;
        reason="controller_result_lost";
        goto done;
    }
    if(!final_received || f.magic!=MAGIC_FINAL || f.seq!=4 ||
       f.worker!=p.worker || !f.gate_opened || !f.worker_armed ||
       !f.waited)goto done;
    o.controller_waited=f.waited;
    o.controller_worker_fds_closed=f.worker_fds_closed;
    if(WIFSIGNALED(f.raw_status) &&
       WTERMSIG(f.raw_status)==SIGTERM)
        o.worker_observed_term=1;
    if(which==CANARY) {
        o.canary_survived=canary.pid>0 && !canary.reaped &&
            getpgid(canary.pid)==canary.pid &&
            getsid(canary.pid)==sid &&
            bsd_owned(canary.pid,owner,canary.pid);
    }
    if(which==POSITIVE || which==CANARY) {
        accepted=o.worker_observed_term && o.term_attempts==1 &&
                 o.term_succeeded && o.worker_armed &&
                 o.worker_default_term && o.worker_unblocked_term &&
                 (which!=CANARY || o.canary_survived);
    } else if(which==NO_SIGDEF || which==NO_SIGMASK) {
        accepted=!o.worker_observed_term && WIFEXITED(f.raw_status) &&
                 WEXITSTATUS(f.raw_status)==24 &&
                 o.term_attempts==1 && o.term_succeeded &&
                 o.worker_armed;
    } else if(which==DEADLINE) {
        accepted=!o.worker_observed_term && WIFEXITED(f.raw_status) &&
                 WEXITSTATUS(f.raw_status)==24 &&
                 o.term_attempts==0 && !o.term_succeeded &&
                 o.admission_cutoff_expired && o.outer_live_at_refusal;
    } else if(which==ANCHOR_LOST) {
        accepted=!o.anchor_held && o.anchor_loss_gate_checked &&
                 !o.after_loss_attempts && !o.term_attempts &&
                 !o.term_succeeded && o.worker_spawned &&
                 o.worker_armed && o.controller_waited &&
                 !o.worker_observed_term && WIFEXITED(f.raw_status) &&
                 WEXITSTATUS(f.raw_status)==24;
    }
    reason=which==ANCHOR_LOST && o.after_loss_attempts ?
           "anchor_gate_violation" : "typed_result";
done: ;
    /* Signal qualification CLOSED before held PGID or PID is released.
       Real close results are part of the VERIFIED cleanup contract. */
    int owner_fd_ok=1;
    if(!close_fd(&controller.input))owner_fd_ok=0;
    if(anchor.pid>0 && !anchor.reaped)
        (void)send_char(anchor.input,'Q',outer_deadline);
    if(canary.pid>0 && !canary.reaped)
        (void)send_char(canary.input,'Q',outer_deadline);
    if(!close_fd(&anchor.input))owner_fd_ok=0;
    if(!close_fd(&canary.input))owner_fd_ok=0;
    int c_ok=controller.pid<=0 || wait_child(&controller,outer_deadline);
    int a_ok=anchor.pid<=0 || wait_child(&anchor,outer_deadline);
    int y_ok=canary.pid<=0 || wait_child(&canary,outer_deadline);
    o.owner_children_reaped=c_ok&&a_ok&&y_ok;
    if(controller.pid>0 &&
       (!controller.reaped||!WIFEXITED(controller.status)||
        WEXITSTATUS(controller.status)!=0))o.owner_children_reaped=0;
    if(anchor.pid>0 &&
       (!anchor.reaped||!WIFEXITED(anchor.status)||
        WEXITSTATUS(anchor.status)!=0))o.owner_children_reaped=0;
    if(canary.pid>0 &&
       (!canary.reaped||!WIFEXITED(canary.status)||
        WEXITSTATUS(canary.status)!=0))o.owner_children_reaped=0;
    if(clock_ms()>=outer_deadline)o.owner_children_reaped=0;
    if(!close_child(&controller))owner_fd_ok=0;
#ifdef C3B02_FAULT_OWNER_CLOSE
    if(which==POSITIVE && anchor.output>=0)
        inject_close_error_once=1; /* real close happens, status injected */
#endif
    if(!close_child(&anchor))owner_fd_ok=0;
    if(!close_child(&canary))owner_fd_ok=0;
    if(!close_fd(owner_dir))owner_fd_ok=0;
    o.owner_fds_closed=owner_fd_ok && managed_fd_close_ok &&
                        clock_ms()<outer_deadline;
    /* A missing Controller FINAL cannot upgrade Worker status: T08 remains
       UNKNOWN/UNRESOLVED even after the Owner reaps all direct children. */
    o.cleanup_complete=o.owner_children_reaped && o.owner_fds_closed &&
        (!o.worker_spawned || o.controller_worker_fds_closed) &&
        which!=RESULT_LOST;
#ifdef C3B02_MUT_OMIT_SIGDEF
    if(which==POSITIVE&&!accepted && o.owner_children_reaped &&
       o.owner_fds_closed && !o.controller_worker_fds_closed &&
       !o.cleanup_complete && o.term_attempts==0 &&
       !strcmp(reason,"worker_signal_ineligible") &&
       !o.worker_default_term && o.worker_unblocked_term) {
        puts("C3B02_MUTANT name=omit-sigdef worker_default_term=0 "
             "worker_unblocked_term=1 term_attempts=0 cleanup_complete=0");
    }
#endif
#ifdef C3B02_MUT_OMIT_SIGMASK
    if(which==POSITIVE&&!accepted && o.owner_children_reaped &&
       o.owner_fds_closed && !o.controller_worker_fds_closed &&
       !o.cleanup_complete && o.term_attempts==0 &&
       !strcmp(reason,"worker_signal_ineligible") &&
       o.worker_default_term && !o.worker_unblocked_term) {
        puts("C3B02_MUTANT name=omit-sigmask worker_default_term=1 "
             "worker_unblocked_term=0 term_attempts=0 cleanup_complete=0");
    }
#endif
#ifdef C3B02_MUT_CTRL_GROUP
    if(which==POSITIVE&&!accepted&&o.cleanup_complete&&o.term_attempts==0 &&
       !strcmp(reason,"controller_group") &&
       !o.controller_group_leader && !o.worker_spawned) {
        puts("C3B02_MUTANT name=omit-controller-group controller_group_leader=0 "
             "worker_spawned=0 term_attempts=0 cleanup_complete=1");
    }
#endif
#ifdef C3B02_MUT_SKIP_ANCHOR_CHECK
    if(which==ANCHOR_LOST && o.anchor_loss_gate_checked &&
       o.worker_armed && o.after_loss_attempts==1 &&
       o.term_attempts==1 && !o.term_succeeded &&
       o.controller_waited && o.cleanup_complete) {
        puts("C3B02_FAULT name=stale-anchor-gate gate_checked=1 "
             "worker_armed=1 after_loss_attempts=1 term_attempts=1 "
             "native_signals=0 cleanup_complete=1");
    }
#endif
#ifdef C3B02_FAULT_OWNER_CLOSE
    if(which==POSITIVE && !o.owner_fds_closed &&
       o.controller_worker_fds_closed && !o.cleanup_complete) {
        puts("C3B02_FAULT name=owner-fd-close owner_fds_closed=0 "
             "controller_worker_fds_closed=1 cleanup_complete=0");
    }
#endif
#ifdef C3B02_FAULT_CONTROLLER_CLOSE
    if(which==POSITIVE && o.owner_fds_closed &&
       !o.controller_worker_fds_closed && !o.cleanup_complete) {
        puts("C3B02_FAULT name=controller-fd-close owner_fds_closed=1 "
             "controller_worker_fds_closed=0 cleanup_complete=0");
    }
#endif
    /* Missing a Controller FINAL does not prove a close() error. */
    if(!o.owner_fds_closed ||
       (o.controller_waited && !o.controller_worker_fds_closed))
        reason="fd_close";
    if(which==ANCHOR_LOST && o.after_loss_attempts)
        reason="anchor_gate_violation";
    if(!accepted || !o.owner_children_reaped ||
       (which==RESULT_LOST ? o.cleanup_complete : !o.cleanup_complete))
        return block_fail(reason);
    printf("C3B02_RESULT mode=%s "
           "anchor_held=%d controller_group_leader=%d "
           "controller_inherited_ignore=%d controller_inherited_block=%d "
           "worker_spawned=%d worker_default_term=%d "
           "worker_unblocked_term=%d worker_armed=%d "
           "term_attempts=%d term_succeeded=%d controller_waited=%d "
           "worker_observed_term=%d admission_cutoff_expired=%d "
           "outer_live_at_refusal=%d gate_opened=%d cleanup_complete=%d "
           "canary_survived=%d worker_result_unknown=%d "
           "result_lost_after_wait=%d owner_children_reaped=%d "
           "anchor_loss_gate_checked=%d after_loss_attempts=%d "
           "owner_fds_closed=%d controller_worker_fds_closed=%d "
           "reuse_proven=0 g2_qualified=0\n",
           mode,o.anchor_held,o.controller_group_leader,
           o.controller_inherited_ignore,o.controller_inherited_block,
           o.worker_spawned,o.worker_default_term,o.worker_unblocked_term,
           o.worker_armed,o.term_attempts,o.term_succeeded,
           o.controller_waited,o.worker_observed_term,
           o.admission_cutoff_expired,o.outer_live_at_refusal,
           o.gate_opened,o.cleanup_complete,o.canary_survived,
           o.worker_result_unknown,o.result_lost_after_wait,
           o.owner_children_reaped,o.anchor_loss_gate_checked,
           o.after_loss_attempts,o.owner_fds_closed,
           o.controller_worker_fds_closed);
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=3)return block_fail("args");
    int dir=-1;
    if(!root_owned(argv[2],argv[0],&dir))return block_fail("private_root");
    const char *role=argv[1];
    int value=0;
    if(!strcmp(role,"__anchor")) {
        value=anchor_role();
    } else if(!strcmp(role,"__canary")) {
        value=canary_role();
    } else if(!strcmp(role,"__controller")) {
        value=controller_role(argv[0],argv[2],dir);
    } else if(!strcmp(role,"__worker")) {
        value=worker_role(dir);
    } else {
        value=owner_role(role,argv[0],argv[2],&dir);
    }
    if(!close_fd(&dir) && value==0)
        return block_fail("role_root_dir_fd_close");
    return value;
}
#endif
