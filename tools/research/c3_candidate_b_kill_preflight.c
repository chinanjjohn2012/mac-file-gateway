/*
 * C3 Candidate B B03-R2 PRE-SIGNAL SAFETY PREFLIGHT ONLY.
 * This is a standalone research binary, not the B-03 forced-KILL helper.
 * It sends NO group TERM/KILL and does not accept PID/PGID/command arguments.
 *
 * Owner -> held self-led Anchor; Owner -> self-led Controller -> Worker
 * Worker joins sibling Anchor PGID with Darwin posix_spawn before gate.
 * Only Controller waits Worker. Owner alone waits Anchor/Controller.
 * All enrolled children cooperate and independently self-expire on failure.
 * This does NOT qualify orphan-prone T04/T08b/T10 or G2.
 */
#ifndef __APPLE__
#include <stdio.h>
int main(void) { puts("C3B03_R2_NOT_RUN_NON_DARWIN"); return 77; }
#else
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <sys/event.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
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
enum { MAGIC_READY=0x43334271, MAGIC_SETUP=0x43334272,
       MAGIC_PROPOSAL=0x43334273, MAGIC_ARMED=0x43334274,
       MAGIC_FINAL=0x43334275, MAGIC_ORPHAN_CANCEL=0x43334276 };
enum { ANCHOR=1, CONTROLLER=2, WORKER=3 };
typedef struct { pid_t pid; int input,output,reaped,status; } Child;
typedef struct {
    int magic,role,seq,term_ignored;
    pid_t pid,ppid,pgid,sid;
} Ready;
typedef struct {
    int magic,seq; pid_t owner,anchor,sid; long long deadline;
} Setup;
typedef struct {
    int magic,seq,worker_started,worker_term_ignored;
    pid_t worker,parent,pgid,sid;
} Proposal;
typedef struct { int magic,seq,armed; pid_t worker; } Armed;
typedef struct {
    int magic,seq,waited,status,worker_fds_closed; pid_t worker;
} Final;
typedef struct {
    int magic,seq,waited,status,fds_closed; pid_t worker;
} OrphanCancelFinal;
static int close_ok=1;

static long long clock_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}
static long remaining(long long deadline) {
    long long d=deadline-clock_ms();
    return d<=0?0:d>200?200:(long)d;
}
static void pause_short(void) {
    struct timespec t={.tv_sec=0,.tv_nsec=10000000L};
    while(nanosleep(&t,&t)<0 && errno==EINTR){}
}
static int fd_close(int *fd) {
    if(*fd<0)return 1;
    int v=*fd;*fd=-1;
    int ok=close(v)==0;
    if(!ok)close_ok=0;
    return ok;
}
static int child_close(Child *c) {
    int a=fd_close(&c->input),b=fd_close(&c->output);
    return a&&b;
}
static int pipe_private(int fds[2]) {
    if(pipe(fds))return 0;
    if(fcntl(fds[0],F_SETFD,FD_CLOEXEC)<0 ||
       fcntl(fds[1],F_SETFD,FD_CLOEXEC)<0) {
        close(fds[0]);close(fds[1]);fds[0]=fds[1]=-1;
        return 0;
    }
    return 1;
}
static int read_exact(int fd,void *p,size_t len,long long deadline) {
    size_t used=0;unsigned char *dst=(unsigned char*)p;
    while(used<len && remaining(deadline)>0) {
        struct pollfd f={.fd=fd,.events=POLLIN|POLLHUP};
        int rc=poll(&f,1,(int)remaining(deadline));
        if(rc<0&&errno==EINTR)continue;
        if(rc<0)return 0;
        if(rc==0)continue;
        ssize_t n=read(fd,dst+used,len-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return 0;
        used+=(size_t)n;
    }
    return used==len;
}
static int write_exact(int fd,const void *p,size_t len,long long deadline) {
    if(remaining(deadline)<=0)return 0;
    for(;;) {
        ssize_t n=write(fd,p,len); /* small single-writer bounded frame */
        if(n<0&&errno==EINTR&&remaining(deadline)>0)continue;
        return n==(ssize_t)len;
    }
}
static int send_byte(int fd,char b,long long deadline) {
    return write_exact(fd,&b,1,deadline);
}
static int read_byte(int fd,char *b,long long deadline) {
    return read_exact(fd,b,1,deadline);
}
static int child_wait(Child *c,long long deadline) {
    if(c->pid<=0)return 1;
    if(c->reaped)return 1;
    while(remaining(deadline)>0) {
        int status=0;
        pid_t ret=waitpid(c->pid,&status,WNOHANG);
        if(ret==c->pid){c->reaped=1;c->status=status;return 1;}
        if(ret<0&&errno==EINTR)continue;
        if(ret<0)return 0;
        pause_short();
    }
    return 0;
}
static int sig_setup(void) {
    struct sigaction s,now;
    memset(&s,0,sizeof s);
    s.sa_handler=SIG_DFL;
    if(sigemptyset(&s.sa_mask) ||
       sigaction(SIGCHLD,&s,NULL) ||
       sigaction(SIGCHLD,NULL,&now) ||
       now.sa_handler!=SIG_DFL ||
       (now.sa_flags&SA_NOCLDWAIT))return 0;
    s.sa_handler=SIG_IGN;
    if(sigaction(SIGPIPE,&s,NULL) ||
       sigaction(SIGPIPE,NULL,&now) ||
       now.sa_handler!=SIG_IGN)return 0;
    return 1;
}
static int ignore_term(void) {
    struct sigaction s,now;
    memset(&s,0,sizeof s);s.sa_handler=SIG_IGN;
    if(sigemptyset(&s.sa_mask) ||
       sigaction(SIGTERM,&s,NULL) ||
       sigaction(SIGTERM,NULL,&now))return 0;
    return now.sa_handler==SIG_IGN;
}
static int term_ignored(void) {
    struct sigaction s;
    return sigaction(SIGTERM,NULL,&s)==0&&s.sa_handler==SIG_IGN;
}
static int bsd_parent(pid_t pid,pid_t parent,pid_t group) {
    struct proc_bsdinfo b;
    int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&b,sizeof b);
    return n==(int)sizeof b &&
           (pid_t)b.pbi_pid==pid &&
           (pid_t)b.pbi_ppid==parent &&
           (pid_t)b.pbi_pgid==group;
}
static int private_root(const char *root,const char *self,int *out) {
    if(!root||root[0]!='/'||!self)return 0;
    size_t len=strlen(root);
    if(strncmp(self,root,len) ||
       strcmp(self+len,"/c3_candidate_b_kill_preflight"))return 0;
    int dir=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return 0;
    struct stat st;
    if(fstat(dir,&st)||!S_ISDIR(st.st_mode)||
       st.st_uid!=geteuid()||(st.st_mode&0077))goto bad;
    int marker=openat(dir,"C3B03_R2_SYNTHETIC",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(marker<0)goto bad;
    char expected[16]={0};
    ssize_t n=read(marker,expected,sizeof expected);
    int valid=(!fstat(marker,&st)&&S_ISREG(st.st_mode)&&
               st.st_uid==geteuid()&&st.st_nlink==1&&
               n==9&&!memcmp(expected,"synthetic",9));
    if(!fd_close(&marker)||!valid)goto bad;
    int exe=openat(dir,"c3_candidate_b_kill_preflight",
                   O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(exe<0)goto bad;
    valid=(!fstat(exe,&st)&&S_ISREG(st.st_mode)&&
           st.st_uid==geteuid()&&st.st_nlink==1&&(st.st_mode&0111));
    if(!fd_close(&exe)||!valid)goto bad;
    *out=dir;return 1;
bad:
    fd_close(&dir);return 0;
}
static int spawn_role(const char *self,const char *root,int dir,
                      const char *role,int group_enabled,pid_t group,
                      Child *child) {
    int in[2]={-1,-1},out[2]={-1,-1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int fa=0,at=0,ok=0;
    if(!pipe_private(in)||!pipe_private(out))goto done;
    if(posix_spawn_file_actions_init(&actions))goto done;
    fa=1;
    if(posix_spawn_file_actions_addfchdir_np(&actions,dir) ||
       posix_spawn_file_actions_adddup2(&actions,in[0],STDIN_FILENO) ||
       posix_spawn_file_actions_adddup2(&actions,out[1],STDOUT_FILENO) ||
       posix_spawn_file_actions_addclose(&actions,in[0]) ||
       posix_spawn_file_actions_addclose(&actions,in[1]) ||
       posix_spawn_file_actions_addclose(&actions,out[0]) ||
       posix_spawn_file_actions_addclose(&actions,out[1]) ||
       posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,
                                       "/dev/null",O_WRONLY,0))goto done;
    if(posix_spawnattr_init(&attr))goto done;
    at=1;
    sigset_t defaults,empty;
    if(sigemptyset(&defaults)||sigaddset(&defaults,SIGPIPE) ||
       sigaddset(&defaults,SIGTERM)||sigemptyset(&empty) ||
       posix_spawnattr_setsigdefault(&attr,&defaults) ||
       posix_spawnattr_setsigmask(&attr,&empty))goto done;
    short flags=POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK;
    if(group_enabled) {
        if(posix_spawnattr_setpgroup(&attr,group))goto done;
        flags|=POSIX_SPAWN_SETPGROUP;
    }
    if(posix_spawnattr_setflags(&attr,flags))goto done;
    char *const argv[]={(char*)self,(char*)role,(char*)root,NULL};
    int err=posix_spawn(&child->pid,self,&actions,&attr,argv,environ);
    if(err){errno=err;child->pid=-1;goto done;}
    child->input=in[1];in[1]=-1;
    child->output=out[0];out[0]=-1;
    ok=1;
done:
    if(at)posix_spawnattr_destroy(&attr);
    if(fa)posix_spawn_file_actions_destroy(&actions);
    fd_close(&in[0]);fd_close(&in[1]);
    fd_close(&out[0]);fd_close(&out[1]);
    return ok;
}
static Ready self_ready(int role) {
    Ready r={.magic=MAGIC_READY,.role=role,.seq=1,
             .pid=getpid(),.ppid=getppid(),
             .pgid=getpgid(0),.sid=getsid(0),
             .term_ignored=term_ignored()};
    return r;
}
static int anchor_role(void) {
    alarm(8); /* own-process expiry, never a group signal */
    if(!sig_setup()||!ignore_term()||getpgid(0)!=getpid())return 41;
    Ready ready=self_ready(ANCHOR);
    long long until=clock_ms()+7500;
    if(!ready.term_ignored ||
       !write_exact(STDOUT_FILENO,&ready,sizeof ready,until))return 42;
    char q=0;
    if(!read_byte(STDIN_FILENO,&q,until))return 0;
    return q=='Q'?0:43;
}
static int worker_role(void) {
    alarm(5);
    if(!sig_setup()||!ignore_term())return 51;
    long long until=clock_ms()+4500;
    Ready ready=self_ready(WORKER);
    if(!ready.term_ignored ||
       !write_exact(STDOUT_FILENO,&ready,sizeof ready,until))return 52;
    char gate=0;
    if(!read_byte(STDIN_FILENO,&gate,until))return 0;
    if(gate!='G')return 0;
    if(!send_byte(STDOUT_FILENO,'A',until))return 53;
    char q=0;
    if(!read_byte(STDIN_FILENO,&q,until))return 24;
    return q=='Q'?24:54;
}
static int controller_role(const char *self,const char *root,int dir) {
    alarm(8);
    if(!sig_setup()||getpgid(0)!=getpid())return 61;
    long long until=clock_ms()+7500;
    Ready ready=self_ready(CONTROLLER);
    if(!write_exact(STDOUT_FILENO,&ready,sizeof ready,until))return 62;
    Setup setup;
    if(!read_exact(STDIN_FILENO,&setup,sizeof setup,until))return 0;
    if(setup.magic!=MAGIC_SETUP||setup.seq!=2 ||
       setup.owner!=getppid()||setup.anchor<=0||setup.sid<=0 ||
       setup.deadline<=clock_ms()||
       getpgid(setup.anchor)!=setup.anchor||
       getsid(setup.anchor)!=setup.sid||
       !bsd_parent(setup.anchor,setup.owner,setup.anchor))return 63;
    Child worker={.pid=-1,.input=-1,.output=-1};
    if(!spawn_role(self,root,dir,"__worker",1,setup.anchor,&worker))
        return 64;
    Ready wr;
    int member=read_exact(worker.output,&wr,sizeof wr,setup.deadline) &&
       wr.magic==MAGIC_READY&&wr.role==WORKER&&wr.seq==1 &&
       wr.pid==worker.pid&&wr.ppid==getpid()&&
       wr.pgid==setup.anchor&&wr.sid==setup.sid&&wr.term_ignored &&
       getpgid(worker.pid)==setup.anchor&&getsid(worker.pid)==setup.sid &&
       bsd_parent(worker.pid,getpid(),setup.anchor);
    Proposal p={.magic=MAGIC_PROPOSAL,.seq=3,.worker_started=member,
                .worker_term_ignored=member?wr.term_ignored:0,
                .worker=member?wr.pid:-1,
                .parent=member?wr.ppid:-1,
                .pgid=member?wr.pgid:-1,.sid=member?wr.sid:-1};
    int sent=write_exact(STDOUT_FILENO,&p,sizeof p,setup.deadline);
    char grant='N';
    if(sent) (void)read_byte(STDIN_FILENO,&grant,setup.deadline);
    int opened=member&&grant=='G' &&
        getpgid(worker.pid)==setup.anchor &&
        bsd_parent(worker.pid,getpid(),setup.anchor);
    (void)send_byte(worker.input,opened?'G':'N',setup.deadline);
    char armed_byte=0;
    Armed armed={.magic=MAGIC_ARMED,.seq=4,.worker=worker.pid,.armed=0};
    if(opened&&read_byte(worker.output,&armed_byte,setup.deadline)&&
       armed_byte=='A'&&getpgid(worker.pid)==setup.anchor)
        armed.armed=1;
    int arm_sent=sent&&write_exact(STDOUT_FILENO,&armed,sizeof armed,
                                  setup.deadline);
    char finish='N';
    if(arm_sent)(void)read_byte(STDIN_FILENO,&finish,setup.deadline);
    (void)send_byte(worker.input,'Q',setup.deadline);
    int in_ok=fd_close(&worker.input);
    Final f={.magic=MAGIC_FINAL,.seq=5,.worker=worker.pid};
    if(child_wait(&worker,setup.deadline)){
        f.waited=1;f.status=worker.status;
    }
    f.worker_fds_closed=in_ok&&child_close(&worker)&&close_ok;
    if(!write_exact(STDOUT_FILENO,&f,sizeof f,setup.deadline))return 65;
    return member&&opened&&armed.armed&&finish=='Q'&&
           f.waited&&WIFEXITED(f.status)&&
           WEXITSTATUS(f.status)==24&&f.worker_fds_closed ? 0 : 66;
}
static int owner_role(const char *self,const char *root,int *rootfd) {
    alarm(11); /* self-expiry backstop; NEVER group signal */
    int dir=*rootfd;
    if(!sig_setup())return 70;
    Child anchor={.pid=-1,.input=-1,.output=-1};
    Child ctrl={.pid=-1,.input=-1,.output=-1};
    const pid_t owner=getpid(),sid=getsid(0);
    const long long deadline=clock_ms()+10000;
    const long long admission_cutoff=deadline-5000;
    const char *phase="start";
    int trusted=0,joined=0,armed=0,waited=0,owner_reaped=0;
    int owner_fds=0,anchor_ready=0,controller_ready=0;
    if(sid<=0||deadline<=admission_cutoff)goto done;
    phase="anchor_spawn";
    if(!spawn_role(self,root,dir,"__anchor",1,0,&anchor))goto done;
    Ready a;
    phase="anchor_ready";
    if(!read_exact(anchor.output,&a,sizeof a,admission_cutoff) ||
       a.magic!=MAGIC_READY||a.seq!=1||a.role!=ANCHOR||
       a.pid!=anchor.pid||a.ppid!=owner||a.pgid!=a.pid||
       a.sid!=sid||!a.term_ignored||
       getpgid(anchor.pid)!=anchor.pid||getsid(anchor.pid)!=sid||
       !bsd_parent(anchor.pid,owner,anchor.pid))goto done;
    anchor_ready=1;
    phase="controller_spawn";
    if(!spawn_role(self,root,dir,"__controller",1,0,&ctrl))goto done;
    Ready c;
    phase="controller_ready";
    if(!read_exact(ctrl.output,&c,sizeof c,admission_cutoff) ||
       c.magic!=MAGIC_READY||c.seq!=1||c.role!=CONTROLLER||
       c.pid!=ctrl.pid||c.ppid!=owner||c.pgid!=c.pid||
       c.sid!=sid||c.pgid==a.pgid||
       getpgid(ctrl.pid)!=ctrl.pid||getsid(ctrl.pid)!=sid||
       !bsd_parent(ctrl.pid,owner,ctrl.pid))goto done;
    controller_ready=1;
    Setup setup={.magic=MAGIC_SETUP,.seq=2,.owner=owner,
                 .anchor=anchor.pid,.sid=sid,.deadline=deadline};
    phase="setup";
    if(!write_exact(ctrl.input,&setup,sizeof setup,admission_cutoff))
        goto done;
    Proposal p;
    phase="proposal";
    if(!read_exact(ctrl.output,&p,sizeof p,admission_cutoff) ||
       p.magic!=MAGIC_PROPOSAL||p.seq!=3||!p.worker_started||
       !p.worker_term_ignored||p.worker<=0||
       p.parent!=ctrl.pid||p.pgid!=anchor.pid||p.sid!=sid||
       !bsd_parent(p.worker,ctrl.pid,anchor.pid)||
       getpgid(p.worker)!=anchor.pid||getsid(p.worker)!=sid||
       getpgid(anchor.pid)!=anchor.pid||
       getpgid(ctrl.pid)!=ctrl.pid)goto done;
    joined=1;
    phase="grant";
    if(!send_byte(ctrl.input,'G',admission_cutoff))goto done;
    Armed ar;
    phase="armed";
    if(!read_exact(ctrl.output,&ar,sizeof ar,admission_cutoff) ||
       ar.magic!=MAGIC_ARMED||ar.seq!=4||
       ar.worker!=p.worker||!ar.armed||
       getpgid(p.worker)!=anchor.pid||
       !bsd_parent(p.worker,ctrl.pid,anchor.pid))goto done;
    armed=1;
    phase="cooperative_finish";
    trusted=1;
done: ;
    /* No group signal capability exists in this preflight binary. */
    if(ctrl.pid>0&&!ctrl.reaped)
        (void)send_byte(ctrl.input,'Q',deadline);
    if(anchor.pid>0&&!anchor.reaped)
        (void)send_byte(anchor.input,'Q',deadline);
    int f_ok=0;
    if(trusted) {
        Final f;
        f_ok=read_exact(ctrl.output,&f,sizeof f,deadline)&&
             f.magic==MAGIC_FINAL&&f.seq==5&&
             f.worker>0&&f.waited&&f.worker_fds_closed&&
             WIFEXITED(f.status)&&WEXITSTATUS(f.status)==24;
    }
    waited=trusted&&f_ok;
    int ctrl_in=fd_close(&ctrl.input),anchor_in=fd_close(&anchor.input);
    int c_ok=child_wait(&ctrl,deadline);
    int a_ok=child_wait(&anchor,deadline);
    owner_reaped=c_ok&&a_ok&&ctrl.reaped&&anchor.reaped&&
        WIFEXITED(ctrl.status)&&WEXITSTATUS(ctrl.status)==0&&
        WIFEXITED(anchor.status)&&WEXITSTATUS(anchor.status)==0;
    int ctrl_close=child_close(&ctrl),anchor_close=child_close(&anchor);
    int dir_close=fd_close(rootfd);
    owner_fds=ctrl_in&&anchor_in&&ctrl_close&&anchor_close&&
              dir_close&&close_ok&&clock_ms()<deadline;
    if(!(trusted&&anchor_ready&&controller_ready&&joined&&armed&&
         waited&&owner_reaped&&owner_fds&&clock_ms()<deadline)) {
        fprintf(stderr,"C3B03_R2_BLOCK phase=%s cleanup=%s\n",
                phase,owner_reaped&&owner_fds?"OBSERVED":"UNRESOLVED");
        return 70;
    }
    puts("C3B03_R2_PREFLIGHT "
         "anchor_held=1 controller_self_led=1 worker_joined=1 "
         "worker_parentage=1 owner_granted=1 worker_armed=1 "
         "controller_waited=1 owner_reaped=1 fds_closed=1 "
         "anchor_term_ignore_ready=1 term_attempts=0 kill_attempts=0 "
         "orphan_preflight_proven=0 reuse_proven=0 g2_qualified=0");
    return 0;
}

/* Deliberately no group signal. NOTE_EXIT observes a non-child but cannot
   furnish a legal worker wait status. The worker self-exits on its own clock. */
static int orphan_marker(int dir,const char *name) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(fd<0)return 0;
    int ok=write(fd,"observed",8)==8;
    return fd_close(&fd)&&ok;
}
static int orphan_worker_role(int dir) {
    alarm(5);
    if(!sig_setup())return 81;
    const pid_t parent=getppid();
    if(parent<=1)return 81;
    const long long deadline=clock_ms()+3800;
    if(!send_byte(STDOUT_FILENO,'W',deadline))return 82;
    for(;;) {
        if(getppid()!=parent)break;
        if(remaining(deadline)<=0)return 83;
        /* Only the living Controller can cooperatively cancel the Worker.
           EOF is NOT a parent-loss witness; independently check getppid(). */
        struct pollfd ctl={.fd=STDIN_FILENO,.events=POLLIN|POLLHUP};
        int n=poll(&ctl,1,20);
        if(n<0&&errno==EINTR)continue;
        if(n<0)return 86;
        if(n>0&&(ctl.revents&POLLIN)) {
            char q=0;
            ssize_t got=read(STDIN_FILENO,&q,1);
            if(got==1&&q=='C')return 24;
            if(got<0&&errno!=EINTR)return 87;
        }
        if(n>0&&(ctl.revents&POLLHUP))pause_short();
    }
    if(!orphan_marker(dir,"C3B03_ORPHAN_REPARENTED"))return 84;
    /* Actual parent loss -> Worker uses its own monotonic self-expiry. */
    const long long self_expiry=clock_ms()+150;
    while(clock_ms()<self_expiry)pause_short();
    if(!orphan_marker(dir,"C3B03_ORPHAN_SELF_EXIT"))return 85;
    return 0;
}
static int orphan_controller_role(const char *self,const char *root,int dir){
    alarm(6);
    if(!sig_setup())return 86;
    const long long deadline=clock_ms()+5000;
    Child worker={.pid=-1,.input=-1,.output=-1};
    if(!spawn_role(self,root,dir,"__orphan_worker",1,0,&worker))return 87;
    char ready=0,release=0;
    if(!read_byte(worker.output,&ready,deadline)||ready!='W')
        goto cancel_worker;
    /* No Worker loss before Owner has installed independent NOTE_EXIT. */
    if(!write_exact(STDOUT_FILENO,&worker.pid,sizeof worker.pid,deadline))
        goto cancel_worker;
    if(!read_byte(STDIN_FILENO,&release,deadline))release='C';
    if(release=='L') {
        /* Only the explicitly released positive case relinquishes waitpid.
           Worker then independently observes reparenting and self-expires. */
        return 0;
    }
cancel_worker:;
    /* Observer registration failure, EOF or malformed release:
       still the lawful Worker parent; cancel, waitpid, close checked FDs. */
    int request=send_byte(worker.input,'C',deadline);
    int input_closed=fd_close(&worker.input);
    OrphanCancelFinal f={.magic=MAGIC_ORPHAN_CANCEL,.seq=2,
                         .worker=worker.pid};
    if(child_wait(&worker,deadline)) {
        f.waited=1;f.status=worker.status;
    }
    f.fds_closed=input_closed&&child_close(&worker)&&close_ok;
    int valid=request&&f.waited&&WIFEXITED(f.status)&&
              WEXITSTATUS(f.status)==24&&f.fds_closed;
    if(valid) (void)write_exact(STDOUT_FILENO,&f,sizeof f,deadline);
    return valid?0:90;
}
static int orphan_owner_role(const char *self,const char *root,int *rootfd){
    alarm(11); /* own-process watchdog, not a group signal */
    int dir=*rootfd;
    if(!sig_setup())return 70;
    Child ctrl={.pid=-1,.input=-1,.output=-1};
    const long long deadline=clock_ms()+7000;
    int kq=-1,registered=0,reparented=0,note_exit=0,self_expiry=0;
    int controller_waited=0,fd_ok=1,worker_known=0,identity=0;
    int released=0,cancel_verified=0;
    pid_t worker=-1;
    if(!spawn_role(self,root,dir,"__orphan_controller",1,0,&ctrl))
        goto orphan_done;
    if(!read_exact(ctrl.output,&worker,sizeof worker,deadline)||worker<=1)
        goto orphan_done;
    worker_known=1;
    /* Bind numeric PID to real Controller child, session and self-led PGID
       before installing the kernel watcher. No user-provided PID exists. */
    const pid_t owner_sid=getsid(0);
    identity=owner_sid>0&&worker!=ctrl.pid&&
             getpgid(worker)==worker&&getsid(worker)==owner_sid&&
             bsd_parent(worker,ctrl.pid,worker);
    if(!identity)goto orphan_done;
#ifdef C3B03_R2_FAULT_KQUEUE_OPEN
    errno=EMFILE; /* fault BEFORE any Controller release */
    goto orphan_done;
#else
    kq=kqueue();
    if(kq<0)goto orphan_done;
#endif
    struct kevent change;
    EV_SET(&change,(uintptr_t)worker,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_ONESHOT,
           NOTE_EXIT,0,NULL);
#ifdef C3B03_R2_FAULT_KEVENT_ADD
    errno=EPERM; /* simulate failed event registration, no release */
    goto orphan_done;
#else
    if(kevent(kq,&change,1,NULL,0,NULL)<0)goto orphan_done;
#endif
    registered=1;
    /* Recheck live parent/group/session once registration is installed. */
    if(getpgid(worker)!=worker||getsid(worker)!=owner_sid||
       !bsd_parent(worker,ctrl.pid,worker))goto orphan_done;
    if(!send_byte(ctrl.input,'L',deadline))goto orphan_done;
    released=1; /* gate: NOT set by a mere positive kqueue descriptor */
    if(!child_wait(&ctrl,deadline)||!WIFEXITED(ctrl.status)||
       WEXITSTATUS(ctrl.status)!=0)goto orphan_done;
    controller_waited=1;
    while(remaining(deadline)>0) {
        struct kevent event;
        struct timespec tick={.tv_sec=0,.tv_nsec=100000000L};
        int n=kevent(kq,NULL,0,&event,1,&tick);
        if(n<0&&errno==EINTR)continue;
        if(n<0)break;
        if(n==1&&event.filter==EVFILT_PROC&&
           event.ident==(uintptr_t)worker&&(event.fflags&NOTE_EXIT)){
            note_exit=1;break;
        }
    }
    struct stat st;
    reparented=fstatat(dir,"C3B03_ORPHAN_REPARENTED",&st,
                       AT_SYMLINK_NOFOLLOW)==0&&S_ISREG(st.st_mode)&&
               st.st_uid==geteuid()&&st.st_nlink==1;
    self_expiry=fstatat(dir,"C3B03_ORPHAN_SELF_EXIT",&st,
                       AT_SYMLINK_NOFOLLOW)==0&&S_ISREG(st.st_mode)&&
                st.st_uid==geteuid()&&st.st_nlink==1;
orphan_done:;
    if(!released&&ctrl.pid>0&&!ctrl.reaped) {
        /* Registration failed: Controller MUST wait its own Worker.
           Cancellation is a protocol byte, not a host PID/PGID signal. */
        int sent=send_byte(ctrl.input,'C',deadline);
        OrphanCancelFinal f={0};
        if(sent&&read_exact(ctrl.output,&f,sizeof f,deadline)&&
           f.magic==MAGIC_ORPHAN_CANCEL&&f.seq==2&&f.worker==worker&&
           f.waited&&WIFEXITED(f.status)&&WEXITSTATUS(f.status)==24&&
           f.fds_closed)
            cancel_verified=1;
    }
    if(!fd_close(&ctrl.input))fd_ok=0;
    if(!child_wait(&ctrl,deadline))controller_waited=0;
    else if(!released&&ctrl.reaped&&WIFEXITED(ctrl.status)&&
            WEXITSTATUS(ctrl.status)==0)
        controller_waited=1; /* actual Owner waitpid on abort path */
    if(!child_close(&ctrl))fd_ok=0;
    if(kq>=0&&!fd_close(&kq))fd_ok=0;
    if(!fd_close(rootfd))fd_ok=0;
    if(!released&&cancel_verified&&controller_waited&&ctrl.reaped&&
       WIFEXITED(ctrl.status)&&WEXITSTATUS(ctrl.status)==0&&
       fd_ok&&close_ok&&clock_ms()<deadline) {
        puts("C3B03_R2_REFUSED reason=observer_not_ready "
             "controller_waited_worker=1 worker_exit_24=1 "
             "fds_closed=1 term_attempts=0 kill_attempts=0");
        return 75; /* expected refusal, NEVER a positive orphan pass */
    }
    if(!(registered&&worker_known&&identity&&released&&
         controller_waited&&note_exit&&reparented&&self_expiry&&
         fd_ok&&close_ok&&clock_ms()<deadline)){
        fprintf(stderr,"C3B03_R2_BLOCK phase=orphan_observation "
                "registered=%d released=%d identity=%d "
                "cancel_verified=%d controller_waited=%d "
                "note_exit=%d reparented=%d self_expiry=%d fd_ok=%d "
                "cleanup=UNRESOLVED\n",registered,released,identity,
                cancel_verified,controller_waited,note_exit,reparented,
                self_expiry,fd_ok);
        return 70;
    }
    puts("C3B03_R2_ORPHAN watcher_registered_before_loss=1 "
         "worker_identity_verified=1 worker_reparented=1 "
         "worker_note_exit=1 worker_self_expiry_witness=1 "
         "controller_legal_wait=0 worker_wait_status_unknown=1 "
         "cleanup_unresolved=1 group_term_attempts=0 group_kill_attempts=0");
    return 0;
}

int main(int argc,char **argv) {
    if(argc!=3)return 70; /* fixed role and private root only */
    int dir=-1;
    if(!private_root(argv[2],argv[0],&dir))return 70;
    int rc=70;
    if(!strcmp(argv[1],"preflight"))
        rc=owner_role(argv[0],argv[2],&dir);
    else if(!strcmp(argv[1],"__anchor"))
        rc=anchor_role();
    else if(!strcmp(argv[1],"__controller"))
        rc=controller_role(argv[0],argv[2],dir);
    else if(!strcmp(argv[1],"__worker"))
        rc=worker_role();
    else if(!strcmp(argv[1],"orphan-preflight"))
        rc=orphan_owner_role(argv[0],argv[2],&dir);
    else if(!strcmp(argv[1],"__orphan_controller"))
        rc=orphan_controller_role(argv[0],argv[2],dir);
    else if(!strcmp(argv[1],"__orphan_worker"))
        rc=orphan_worker_role(dir);
    if(!fd_close(&dir)&&rc==0)return 70;
    return rc;
}
#endif
