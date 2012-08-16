Linux syscalls 
================================
<pre>
#		Name 							EAX		EBX											ECX													EDX												ESI										EDI

0		sys_restart_syscall				0x00	-											-													-												-										-
1		sys_exit						0x01	int error_code								-													-												-										-
2		sys_fork						0x02	struct pt_regs *							-													-												-										-
3		sys_read						0x03	unsigned int fd								char __user *buf									size_t count									-										-
4		sys_write						0x04	unsigned int fd								const char __user *buf								size_t count									-										-
5		sys_open						0x05	const char __user *filename					int flags											int mode										-										-
6		sys_close						0x06	unsigned int fd								-													-												-										-
7		sys_waitpid						0x07	pid_t pid									int __user *stat_addr								int options										-										-
8		sys_creat						0x08	const char __user *pathname					int mode											-												-										-
9		sys_link						0x09	const char __user *oldname					const char __user *newname							-												-										-
10		sys_unlink						0x0a	const char __user *pathname					-													-												-										-
11		sys_execve						0x0b	char __user *								char __user *__user *								char __user *__user *							struct pt_regs *						-
12		sys_chdir						0x0c	const char __user *filename					-													-												-										-
13		sys_time						0x0d	time_t __user *tloc							-													-												-										-
14		sys_mknod						0x0e	const char __user *filename					int mode											unsigned dev									-										-
15		sys_chmod						0x0f	const char __user *filename					mode_t mode											-												-										-
16		sys_lchown16					0x10	const char __user *filename					old_uid_t user										old_gid_t group									-										-
17		not implemented					0x11	-											-													-												-										-
18		sys_stat						0x12	char __user *filename						struct __old_kernel_stat __user *statbuf			-												-										-
19		sys_lseek						0x13	unsigned int fd								off_t offset										unsigned int origin								-										-
20		sys_getpid						0x14	-											-													-												-										-
21		sys_mount						0x15	char __user *dev_name						char __user *dir_name								char __user *type								unsigned long flags						void __user *data
22		sys_oldumount					0x16	char __user *name							-													-												-										-
23		sys_setuid16					0x17	old_uid_t uid								-													-												-										-
24		sys_getuid16					0x18	-											-													-												-										-
25		sys_stime						0x19	time_t __user *tptr							-													-												-										-
26		sys_ptrace						0x1a	long request								long pid											long addr										long data								-
27		sys_alarm						0x1b	unsigned int seconds						-													-												-										-
28		sys_fstat						0x1c	unsigned int fd								struct __old_kernel_stat __user *statbuf			-												-										-
29		sys_pause						0x1d	-											-													-												-										-
30		sys_utime						0x1e	char __user *filename						struct utimbuf __user *times						-												-										-
31		not implemented					0x1f	-											-													-												-										-
32		not implemented					0x20	-											-													-												-										-
33		sys_access						0x21	const char __user *filename					int mode											-												-										-
34		sys_nice						0x22	int increment								-													-												-										-
35		not implemented					0x23	-											-													-												-										-
36		sys_sync						0x24	-											-													-												-										-
37		sys_kill						0x25	int pid										int sig												-												-										-
38		sys_rename						0x26	const char __user *oldname					const char __user *newname							-												-										-
39		sys_mkdir						0x27	const char __user *pathname					int mode											-												-										-
40		sys_rmdir						0x28	const char __user *pathname					-													-												-										-
41		sys_dup							0x29	unsigned int fildes							-													-												-										-
42		sys_pipe						0x2a	int __user *fildes							-													-												-										-
43		sys_times						0x2b	struct tms __user *tbuf						-													-												-										-
44		not implemented					0x2c	-											-													-												-										-
45		sys_brk							0x2d	unsigned long brk							-													-												-										-
46		sys_setgid16					0x2e	old_gid_t gid								-													-												-										-
47		sys_getgid16					0x2f	-											-													-												-										-
48		sys_signal						0x30	int sig										__sighandler_t handler								-												-										-
49		sys_geteuid16					0x31	-											-													-												-										-
50		sys_getegid16					0x32	-											-													-												-										-
51		sys_acct						0x33	const char __user *name						-													-												-										-
52		sys_umount						0x34	char __user *name							int flags											-												-										-
53		not implemented					0x35	-											-													-												-										-
54		sys_ioctl						0x36	unsigned int fd								unsigned int cmd									unsigned long arg								-										-
55		sys_fcntl						0x37	unsigned int fd								unsigned int cmd									unsigned long arg								-										-
56		not implemented					0x38	-											-													-												-										-
57		sys_setpgid						0x39	pid_t pid									pid_t pgid											-												-										-
58		not implemented					0x3a	-											-													-												-										-
59		sys_olduname					0x3b	struct oldold_utsname __user *				-													-												-										-
60		sys_umask						0x3c	int mask									-													-												-										-
61		sys_chroot						0x3d	const char __user *filename					-													-												-										-
62		sys_ustat						0x3e	unsigned dev								struct ustat __user *ubuf							-												-										-
63		sys_dup2						0x3f	unsigned int oldfd							unsigned int newfd									-												-										-
64		sys_getppid						0x40	-											-													-												-										-
65		sys_getpgrp						0x41	-											-													-												-										-
66		sys_setsid						0x42	-											-													-												-										-
67		sys_sigaction					0x43	int sig										const struct old_sigaction __user *act				struct old_sigaction __user *oact				-										-
68		sys_sgetmask					0x44	-											-													-												-										-
69		sys_ssetmask					0x45	int newmask									-													-												-										-
70		sys_setreuid16					0x46	old_uid_t ruid								old_uid_t euid										-												-										-
71		sys_setregid16					0x47	old_gid_t rgid								old_gid_t egid										-												-										-
72		sys_sigsuspend					0x48	int history0								int history1										old_sigset_t mask								-										-
73		sys_sigpending					0x49	old_sigset_t __user *set					-													-												-										-
74		sys_sethostname					0x4a	char __user *name							int len												-												-										-
75		sys_setrlimit					0x4b	unsigned int resource						struct rlimit __user *rlim							-												-										-
76		sys_old_getrlimit				0x4c	unsigned int resource						struct rlimit __user *rlim							-												-										-
77		sys_getrusage					0x4d	int who										struct rusage __user *ru							-												-										-
78		sys_gettimeofday				0x4e	struct timeval __user *tv					struct timezone __user *tz							-												-										-
79		sys_settimeofday				0x4f	struct timeval __user *tv					struct timezone __user *tz							-												-										-
80		sys_getgroups16					0x50	int gidsetsize								old_gid_t __user *grouplist							-												-										-
81		sys_setgroups16					0x51	int gidsetsize								old_gid_t __user *grouplist							-												-										-
82		sys_old_select					0x52	struct sel_arg_struct __user *arg			-													-												-										-
83		sys_symlink						0x53	const char __user *old						const char __user *new								-												-										-
84		sys_lstat						0x54	char __user *filename						struct __old_kernel_stat __user *statbuf			-												-										-
85		sys_readlink					0x55	const char __user *path						char __user *buf									int bufsiz										-										-
86		sys_uselib						0x56	const char __user *library					-													-												-										-
87		sys_swapon						0x57	const char __user *specialfile				int swap_flags										-												-										-
88		sys_reboot						0x58	int magic1									int magic2											unsigned int cmd								void __user *arg						-
89		sys_old_readdir					0x59	unsigned int								struct old_linux_dirent __user *					unsigned int									-										-
90		sys_old_mmap					0x5a	struct mmap_arg_struct __user *arg			-													-												-										-
91		sys_munmap						0x5b	unsigned long addr							size_t len											-												-										-
92		sys_truncate					0x5c	const char __user *path						long length											-												-										-
93		sys_ftruncate					0x5d	unsigned int fd								unsigned long length								-												-										-
94		sys_fchmod						0x5e	unsigned int fd								mode_t mode											-												-										-
95		sys_fchown16					0x5f	unsigned int fd								old_uid_t user										old_gid_t group									-										-
96		sys_getpriority					0x60	int which									int who												-												-										-
97		sys_setpriority					0x61	int which									int who												int niceval										-										-
98		not implemented					0x62	-											-													-												-										-
99		sys_statfs						0x63	const char __user * path					struct statfs __user *buf							-												-										-
100		sys_fstatfs						0x64	unsigned int fd								struct statfs __user *buf							-												-										-
101		sys_ioperm						0x65	unsigned long								unsigned long										int												-										-
102		sys_socketcall					0x66	int call									unsigned long __user *args							-												-										-
103		sys_syslog						0x67	int type									char __user *buf									int len											-										-
104		sys_setitimer					0x68	int which									struct itimerval __user *value						struct itimerval __user *ovalue					-										-
105		sys_getitimer					0x69	int which									struct itimerval __user *value						-												-										-
106		sys_newstat						0x6a	char __user *filename						struct stat __user *statbuf							-												-										-
107		sys_newlstat					0x6b	char __user *filename						struct stat __user *statbuf							-												-										-
108		sys_newfstat					0x6c	unsigned int fd								struct stat __user *statbuf							-												-										-
109		sys_uname						0x6d	struct old_utsname __user *					-													-												-										-
110		sys_iopl						0x6e	unsigned int								struct pt_regs *									-												-										-
111		sys_vhangup						0x6f	-											-													-												-										-
112		not implemented					0x70	-											-													-												-										-
113		sys_vm86old						0x71	struct vm86_struct __user *					struct pt_regs *									-												-										-
114		sys_wait4						0x72	pid_t pid									int __user *stat_addr								int options										struct rusage __user *ru				-
115		sys_swapoff						0x73	const char __user *specialfile				-													-												-										-
116		sys_sysinfo						0x74	struct sysinfo __user *info					-													-												-										-
117		sys_ipc							0x75	-											-													-												-										-
118		sys_fsync						0x76	unsigned int fd								-													-												-										-
119		sys_sigreturn					0x77	struct pt_regs *regs						-													-												-										-
120		sys_clone						0x78	unsigned long								unsigned long										unsigned long									unsigned long							struct pt_regs *
121		sys_setdomainname				0x79	char __user *name							int len												-												-										-
122		sys_newuname					0x7a	struct new_utsname 	__user *name			-													-												-										-
123		sys_modify_ldt					0x7b	int	void 									__user *											unsigned long									-										-
124		sys_adjtimex					0x7c	struct timex __user *txc_p					-													-												-										-
125		sys_mprotect					0x7d	unsigned long start							size_t len											unsigned long prot								-										-
126		sys_sigprocmask					0x7e	int how										old_sigset_t __user *set							old_sigset_t __user *oset						-										-
127		not implemented					0x7f	-											-													-												-										-
128		sys_init_module					0x80	void __user *umod							unsigned long len									const char __user *uargs						-										-
129		sys_delete_module				0x81	const char __user *name_user				unsigned int flags									-												-										-
130		not implemented					0x82	-											-													-												-										-
131		sys_quotactl					0x83	unsigned int cmd							const char __user *special							qid_t id										void __user *addr						-
132		sys_getpgid						0x84	pid_t pid									-													-												-										-
133		sys_fchdir						0x85	unsigned int fd								-													-												-										-
134		sys_bdflush						0x86	int func									long data											-												-										-
135		sys_sysfs						0x87	int option									unsigned long arg1									unsigned long arg2								-										-
136		sys_personality					0x88	unsigned int personality					-													-												-										-
137		not implemented					0x89	-											-													-												-										-
138		sys_setfsuid16					0x8a	old_uid_t uid								-													-												-										-
139		sys_setfsgid16					0x8b	old_gid_t gid								-													-												-										-
140		sys_llseek						0x8c	unsigned int fd								unsigned long offset_high							unsigned long offset_low						loff_t __user *result					unsigned int origin
141		sys_getdents					0x8d	unsigned int fd								struct linux_dirent __user *dirent					unsigned int count								-										-
142		sys_select						0x8e	int n										fd_set __user *inp									fd_set __user *outp								fd_set __user *exp						struct timeval __user *tvp
143		sys_flock						0x8f	unsigned int fd								unsigned int cmd									-												-										-
144		sys_msync						0x90	unsigned long start							size_t len											int flags										-										-
145		sys_readv						0x91	unsigned long fd							const struct iovec __user *vec						unsigned long vlen								-										-
146		sys_writev						0x92	unsigned long fd							const struct iovec __user *vec						unsigned long vlen								-										-
147		sys_getsid						0x93	pid_t pid									-													-												-										-
148		sys_fdatasync					0x94	unsigned int fd								-													-												-										-
149		sys_sysctl						0x95	struct __sysctl_args __user *args			-													-												-										-
150		sys_mlock						0x96	unsigned long start							size_t len											-												-										-
151		sys_munlockall					0x97	unsigned long start							size_t len											-												-										-
152		sys_mlockall					0x98	int flags									-													-												-										-
153		sys_munlockall					0x99	-											-													-												-										-
154		sys_sched_setparam				0x9a	pid_t pid									struct sched_param __user *param					-												-										-
155		sys_sched_getparam				0x9b	pid_t pid									struct sched_param __user *param					-												-										-
156		sys_sched_setscheduler			0x9c	pid_t pid									int policy											struct sched_param __user *param				-										-
157		sys_sched_getscheduler			0x9d	pid_t pid									-													-												-										-
158		sys_sched_yield					0x9e	-											-													-												-										-
159		sys_sched_get_priority_max		0x9f	int policy									-													-												-										-
160		sys_sched_get_priority_min		0xa0	int policy									-													-												-										-
161		sys_sched_rr_get_interval		0xa1	pid_t pid									struct timespec __user *interval					-												-										-
162		sys_nanosleep					0xa2	struct timespec __user *rqtp				struct timespec __user *rmtp						-												-										-
163		sys_mremap						0xa3	unsigned long addr							unsigned long old_len								unsigned long new_len							unsigned long flags						unsigned long new_addr
164		sys_setresuid16					0xa4	old_uid_t ruid								old_uid_t euid										old_uid_t suid									-										-
165		sys_getresuid16					0xa5	old_uid_t __user *ruid						old_uid_t __user *euid								old_uid_t __user *suid							-										-
166		sys_vm86						0xa6	unsigned long								unsigned long										struct pt_regs *								-										-
167		not implemented					0xa7	-											-													-												-										-
168		sys_poll						0xa8	struct pollfd __user *ufds					unsigned int nfds									long timeout									-										-
169		sys_nfsservctl					0xa9	int cmd										struct nfsctl_arg __user *arg						void __user *res								-										-
170		sys_setresgid16					0xaa	old_gid_t rgid								old_gid_t egid										old_gid_t sgid									-										-
171		sys_getresgid16					0xab	old_gid_t __user *rgid						old_gid_t __user *egid								old_gid_t __user *sgid							-										-
172		sys_prctl						0xac	int option									unsigned long arg2									unsigned long arg3								unsigned long arg4						unsigned long arg5	
173		sys_rt_sigreturn				0xad	struct pt_regs *							-													-												-										-	
174		sys_rt_sigaction				0xae	int sig										const struct sigaction __user *act					struct sigaction __user *oact					size_t sigsetsize						-	
175		sys_rt_sigprocmask				0xaf	int how										sigset_t __user *set								sigset_t __user *oset							size_t sigsetsize						-	
176		sys_rt_sigpending				0xb0	sigset_t __user *set						size_t sigsetsize									-												-										-	
177		sys_rt_sigtimedwait				0xb1	const sigset_t __user *uthese				siginfo_t __user *uinfo								const struct timespec __user *uts				size_t sigsetsize						-	
178		sys_rt_sigqueueinfo				0xb2	int pid										int sig												siginfo_t __user *uinfo							-										-
179		sys_rt_sigsuspend				0xb3	sigset_t __user *unewset					size_t sigsetsize									-												-										-
180		sys_pread64						0xb4	unsigned int fd								char __user *buf									size_t count									loff_t pos								-
181		sys_pwrite64					0xb5	unsigned int fd								const char __user *buf								size_t count									loff_t pos								-
182		sys_chown16						0xb6	const char __user *filename					old_uid_t user										old_gid_t grouplist								-										-
183		sys_getcwd						0xb7	char __user *buf							unsigned long size									-												-										-
184		sys_capget						0xb8	cap_user_header_t header					cap_user_data_t dataptr								-												-										-
185		sys_capset						0xb9	cap_user_header_t header					const cap_user_data_t data							-												-										-
186		sys_sigaltstack					0xba	const stack_t __user *						stack_t __user *									struct pt_regs *								-										-
187		sys_sendfile					0xbb	int out_fd									int in_fd											off_t __user *offset							size_t count							-
188		not implemented					0xbc	-											-													-												-										-
189		not implemented					0xbd	-											-													-												-										-
190		sys_vfork						0xbe	struct pt_regs *							-													-												-										-
191		sys_getrlimit					0xbf	unsigned int resource						struct rlimit __user *rlim							-												-										-
192		sys_mmap_pgoff					0xc0	-											-													-												-										-
193		sys_truncate64					0xc1	const char __user *path						loff_t length										-												-										-
194		sys_ftruncate64					0xc2	unsigned int fd								loff_t length										-												-										-
195		sys_stat64						0xc3	char __user *filename						struct stat64 __user *statbuf						-												-										-
196		sys_lstat64						0xc4	char __user *filename						struct stat64 __user *statbuf						-												-										-
197		sys_fstat64						0xc5	unsigned long fd							struct stat64 __user *statbuf						-												-										-
198		sys_lchown						0xc6	const char __user *filename					uid_t user											gid_t group										-										-
199		sys_getuid						0xc7	-											-													-												-										-
200		sys_getgid						0xc8	-											-													-												-										-
201		sys_geteuid						0xc9	-											-													-												-										-
202		sys_getegid						0xca	-											-													-												-										-
203		sys_setreuid					0xcb	uid_t ruid									uid_t euid											-												-										-
204		sys_setregid					0xcc	gid_t rgid									gid_t egid											-												-										-
205		sys_getgroups					0xcd	int gidsetsize								gid_t __user *grouplist								-												-										-
206		sys_setgroups					0xce	int gidsetsize								gid_t __user *grouplist								-												-										-
207		sys_fchown16					0xcf	unsigned int fd								uid_t user											gid_t group										-										-
208		sys_setresuid					0xd0	uid_t ruid									uid_t euid											uid_t suid										-										-
209		sys_getresuid					0xd1	uid_t __user *ruid							uid_t __user *euid									uid_t __user *suid								-										-
210		sys_setresgid					0xd2	gid_t rgid									gid_t egid											gid_t sgid										-										-
211		sys_getresgid					0xd3	gid_t __user *rgid							gid_t __user *egid									gid_t __user *sgid								-										-
212		sys_chown						0xd4	const char __user *filename					uid_t user											gid_t group										-										-
213		sys_setuid						0xd5	uid_t uid									-													-												-										-
214		sys_setgid						0xd6	gid_t gid									-													-												-										-
215		sys_setfsuid					0xd7	uid_t uid									-													-												-										-
216		sys_setfsgid					0xd8	gid_t gid									-													-												-										-
217		sys_pivot_root					0xd9	const char __user *new_root					const char __user *put_old							-												-										-
218		sys_mincore						0xda	unsigned long start							size_t len											unsigned char __user * vec						-										-
219		sys_madvise						0xdb	unsigned long start							size_t len											int behavior									-										-
220		sys_getdents64					0xdc	unsigned int fd								struct linux_dirent64 __user *dirent				unsigned int count								-										-
221		sys_fcntl64						0xdd	unsigned int fd								unsigned int cmd									unsigned long arg								-										-
222		not implemented					0xde	-											-													-												-										-
223		not implemented					0xdf	-											-													-												-										-
224		sys_gettid						0xe0	-											-													-												-										-
225		sys_readahead					0xe1	int fd										loff_t offset										size_t count									-										-
226		sys_setxattr					0xe2	const char __user *path						const char __user *name								const void __user *value						size_t size								int flags
227		sys_lsetxattr					0xe3	const char __user *path						const char __user *name								const void __user *value						size_t size								int flags
228		sys_fsetxattr					0xe4	int fd										const char __user *name								const void __user *value						size_t size								int flags
229		sys_getxattr					0xe5	const char __user *path						const char __user *name								void __user *value								size_t size								-
230		sys_lgetxattr					0xe6	const char __user *path						const char __user *name								void __user *value								size_t size								-
231		sys_fgetxattr					0xe7	int fd										const char __user *name								void __user *value								size_t size								-
232		sys_listxattr					0xe8	const char __user *path						char __user *list									size_t size										-										-
233		sys_llistxattr					0xe9	const char __user *path						char __user *list									size_t size										-										-
234		sys_flistxattr					0xea	int fd										char __user *list									size_t size										-										-
235		sys_removexattr					0xeb	const char __user *path						const char __user *name								-												-										-
236		sys_lremovexattr				0xec	const char __user *path						const char __user *name								-												-										-
237		sys_fremovexattr				0xed	int fd										const char __user *name								-												-										-
238		sys_tkill						0xee	int pid										int sig												-												-										-
239		sys_sendfile64					0xef	int out_fd									int in_fd											loff_t __user *offset							size_t count							-
240		sys_futex						0xf0	-											-													-												-										-
241		sys_sched_setaffinity			0xf1	pid_t pid									unsigned int len									unsigned long __user *user_mask_ptr				-										-
242		sys_sched_getaffinity			0xf2	pid_t pid									unsigned int len									unsigned long __user *user_mask_ptr				-										-
243		sys_set_thread_area				0xf3	struct user_desc __user *					-													-												-										-
244		sys_get_thread_area				0xf4	struct user_desc __user *					-													-												-										-
245		sys_io_setup					0xf5	unsigned nr_reqs							aio_context_t __user *ctx							-												-										-
246		sys_io_destroy					0xf6	aio_context_t ctx							-													-												-										-
247		sys_io_getevents				0xf7	aio_context_t ctx_id						long min_nr											long nr											struct io_event __user *events			struct timespec __user *timeout
248		sys_io_submit					0xf8	aio_context_t								long 												struct iocb __user * __user *					-										-
249		sys_io_cancel					0xf9	aio_context_t ctx_id						struct iocb __user *iocb							struct io_event __user *result					-										-
250		sys_fadvise64					0xfa	int fd										loff_t offset										size_t len										int advice								-
251		not implemented					0xfb	-											-													-												-										-
252		sys_exit_group					0xfc	int error_code								-													-												-										-
253		sys_lookup_dcookie				0xfd	u64 cookie64								char __user *buf									size_t len										-										-
254		sys_epoll_create				0xfe	int size									-													-												-										-
255		sys_epoll_ctl					0xff	int epfd									int op												int fd											struct epoll_event __user *event		-
256		sys_epoll_wait					0x100	int epfd									struct epoll_event __user *events					int maxevents									int timeout								-
257		sys_remap_file_pages			0x101	unsigned long start							unsigned long size									unsigned long prot								unsigned long pgoff						unsigned long flags
258		sys_set_tid_address				0x102	int __user *tidptr							-													-												-										-
259		sys_timer_create				0x103	clockid_t which_clock						struct sigevent __user *timer_event_spec			timer_t __user * created_timer_id				-										-
260		sys_timer_settime				0x104	timer_t timer_id							int flags											const struct itimerspec __user *new_setting		struct itimerspec __user *old_setting	-
261		sys_timer_gettime				0x105	timer_t timer_id							struct itimerspec __user *setting					-												-										-
262		sys_timer_getoverrun			0x106	timer_t timer_id							-													-												-										-
263		sys_timer_delete				0x107	timer_t timer_id							-													-												-										-
264		sys_clock_settime				0x108	clockid_t which_clock						const struct timespec __user *tp					-												-										-
265		sys_clock_gettime				0x109	clockid_t which_clock						struct timespec __user *tp							-												-										-
266		sys_clock_getres				0x10a	clockid_t which_clock						struct timespec __user *tp							-												-										-
267		sys_clock_nanosleep				0x10b	clockid_t which_clock						int flags											const struct timespec __user *rqtp				struct timespec __user *rmtp			-
268		sys_statfs64					0x10c	const char __user *path						size_t sz											struct statfs64 __user *buf						-										-
269		sys_fstatfs64					0x10d	unsigned int fd								size_t sz											struct statfs64 __user *buf						-										-
270		sys_tgkill						0x10e	int tgid									int pid												int sig											-										-
271		sys_utimes						0x10f	char __user *filename						struct timeval __user *utimes						-												-										-
272		sys_fadvise64_64				0x110	int fd										loff_t offset 										loff_t len										int advice								-
273		not implemented					0x111	-											-													-												-										-
274		sys_mbind						0x112	-											-													-												-										-
275		sys_get_mempolicy				0x113	int __user *policy							unsigned long __user *nmask							unsigned long maxnode							unsigned long addr						unsigned long flags
276		sys_set_mempolicy				0x114	int mode									unsigned long __user *nmask							unsigned long maxnode							-										-
277		sys_mq_open						0x115	const char __user *name						int oflag											mode_t mode										struct mq_attr __user *attr				-
278		sys_mq_unlink					0x116	const char __user *name						-													-												-										-
279		sys_mq_timedsend				0x117	mqd_t mqdes									const char __user *msg_ptr							size_t msg_len									unsigned int msg_prio					const struct timespec __user *abs_timeout	
280		sys_mq_timedreceive				0x118	mqd_t mqdes									char __user *msg_ptr								size_t msg_len									unsigned int __user *msg_prio			const struct timespec __user *abs_timeout	
281		sys_mq_notify					0x119	mqd_t mqdes									const struct sigevent __user *notification			-												-										-
282		sys_mq_getsetattr				0x11a	mqd_t mqdes									const struct mq_attr __user *mqstat					struct mq_attr __user *omqstat					-										-
283		sys_kexec_load					0x11b	unsigned long entry							unsigned long nr_segments							struct kexec_segment __user *segments			unsigned long flags						-
284		sys_waitid						0x11c	int which									pid_t pid											struct siginfo __user *infop					int options								struct rusage __user *ru
285		not implemented					0x11d	-											-													-												-										-	
286		sys_add_key						0x11e	const char __user *_type					const char __user *_description						const void __user *_payload						size_t plen								key_serial_t
287		sys_request_key					0x11f	const char __user *_type					const char __user *_description						const char __user *_callout_info				key_serial_t destringid					-
288		sys_keyctl						0x120	int cmd										unsigned long arg2									unsigned long arg3								unsigned long arg4						unsigned long arg5
289		sys_ioprio_set					0x121	int which									int who												int ioprio										-										-
290		sys_ioprio_get					0x122	int which									int who												-												-										-
291		sys_inotify_init				0x123	-											-													-												-										-
292		sys_inotify_add_watch			0x124	int fd										const char __user *path								u32 mask										-										-
293		sys_inotify_rm_watch			0x125	int fd										__s32 wd											-												-										-
294		sys_migrate_pages				0x126	pid_t pid									unsigned long maxnode								const unsigned long __user *from				const unsigned long __user *to			-
295		sys_openat						0x127	int dfd										const char __user *filename							int flags										int mode								-
296		sys_mkdirat						0x128	int dfd										const char __user * pathname						int mode										-										-
297		sys_mknodat						0x129	int dfd										const char __user * filename						int mode										unsigned dev							-
298		sys_fchownat					0x12a	int dfd										const char __user *filename							uid_t user										gid_t group								int flag
299		sys_futimesat					0x12b	int dfd										char __user *filename								struct timeval __user *utimes					-										-
300		sys_fstatat64					0x12c	int dfd										char __user *filename								struct stat64 __user *statbuf					int flag								-
301		sys_unlinkat					0x12d	int dfd										const char __user * pathname						int flag										-										-
302		sys_renameat					0x12e	int olddfd									const char __user * oldname							int newdfd										const char __user * newname				-
303		sys_linkat						0x12f	int olddfd									const char __user *oldname							int newdfd										const char __user *newname				int flags
304		sys_symlinkat					0x130	const char __user * oldname					int newdfd											const char __user * newname						-										-
305		sys_readlinkat					0x131	int dfd										const char __user *path								char __user *buf								int bufsiz								-
306		sys_fchmodat					0x132	int dfd										const char __user * filename						mode_t mode										-										-
307		sys_faccessat					0x133	int dfd										const char __user *filename							int mode										-										-
308		sys_pselect6					0x134	-											-													-												-										-
309		sys_ppoll						0x135	struct pollfd __user *ufds					unsigned int nfds									struct timespec __user *tsp						const sigset_t __user *sigmask			size_t sigsetsize
310		sys_unshare						0x136	unsigned long unshare_flags					-													-												-										-
311		sys_set_robust_list				0x137	struct robust_list_head __user *head		size_t len											-												-										-
312		sys_get_robust_list				0x138	int pid										struct robust_list_head __user * __user *head_ptr	size_t __user *len_ptr							-										-
313		sys_splice						0x139	-											-													-												-										-
314		sys_sync_file_range				0x13a	int fd										loff_t offset										loff_t nbytes									unsigned int flags						-
315		sys_tee							0x13b	int fdin									int fdout											size_t len										unsigned int flags						-
316		sys_vmsplice					0x13c	int fd										const struct iovec __user *iov						unsigned long nr_segs							unsigned int flags						-
317		sys_move_pages					0x13d	-											-													-												-										-
318		sys_getcpu						0x13e	unsigned __user *cpu						unsigned __user *node								struct getcpu_cache __user *cache				-										-
319		sys_epoll_pwait					0x13f	-											-													-												-										-
320		sys_utimensat					0x140	int dfd										char __user *filename								struct timespec __user *utimes					int flags								-
321		sys_signalfd					0x141	int ufd										sigset_t __user *user_mask							size_t sizemask									-										-
322		sys_timerfd_create				0x142	int clockid									int flags											-												-										-
323		sys_eventfd						0x143	unsigned int count							-													-												-										-
324		sys_fallocate					0x144	int fd										int mode											loff_t offset									loff_t len								-
325		sys_timerfd_settime				0x145	int ufd										int flags											const struct itimerspec __user *utmr			struct itimerspec __user *otmr			-
326		sys_timerfd_gettime				0x146	int ufd										struct itimerspec __user *otmr						-												-										-
327		sys_signalfd4					0x147	int ufd										sigset_t __user *user_mask							size_t sizemask									int flags								-
328		sys_eventfd2					0x148	unsigned int count							int flags											-												-										-
329		sys_epoll_create1				0x149	int flags									-													-												-										-
330		sys_dup3						0x14a	unsigned int oldfd							unsigned int newfd									int flags										-										-
331		sys_pipe2						0x14b	int __user *fildes							int flags											-												-										-
332		sys_inotify_init1				0x14c	int flags									-													-												-										-
333		sys_preadv						0x14d	unsigned long fd							const struct iovec __user *vec						unsigned long vlen								unsigned long pos_l						unsigned long pos_h
334		sys_pwritev						0x14e	unsigned long fd							const struct iovec __user *vec						unsigned long vlen								unsigned long pos_l						unsigned long pos_h
335		sys_rt_tgsigqueueinfo			0x14f	pid_t tgid									pid_t pid											int sig											siginfo_t __user *uinfo					-	
336		sys_perf_event_open				0x150	struct perf_event_attr __user *attr_uptr	pid_t pid											int cpu											int group_fd							unsigned long flags
337		sys_recvmmsg					0x151	int fd										struct mmsghdr __user *msg							unsigned int vlen								unsigned flags							struct timespec __user *timeout

</pre>