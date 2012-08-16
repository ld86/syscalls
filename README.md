0	i386	restart_syscall		sys_restart_syscall
1	i386	exit			sys_exit
2	i386	fork			ptregs_fork			stub32_fork
3	i386	read			sys_read
4	i386	write			sys_write
5	i386	open			sys_open			compat_sys_open
6	i386	close			sys_close
7	i386	waitpid			sys_waitpid			sys32_waitpid
8	i386	creat			sys_creat
9	i386	link			sys_link
10	i386	unlink			sys_unlink
11	i386	execve			ptregs_execve			stub32_execve
12	i386	chdir			sys_chdir
13	i386	time			sys_time			compat_sys_time
14	i386	mknod			sys_mknod
15	i386	chmod			sys_chmod
16	i386	lchown			sys_lchown16
17	i386	break
18	i386	oldstat			sys_stat
19	i386	lseek			sys_lseek			sys32_lseek
20	i386	getpid			sys_getpid
21	i386	mount			sys_mount			compat_sys_mount
22	i386	umount			sys_oldumount
23	i386	setuid			sys_setuid16
24	i386	getuid			sys_getuid16
25	i386	stime			sys_stime			compat_sys_stime
26	i386	ptrace			sys_ptrace			compat_sys_ptrace
27	i386	alarm			sys_alarm
28	i386	oldfstat		sys_fstat
29	i386	pause			sys_pause
30	i386	utime			sys_utime			compat_sys_utime
31	i386	stty
32	i386	gtty
33	i386	access			sys_access
34	i386	nice			sys_nice
35	i386	ftime
36	i386	sync			sys_sync
37	i386	kill			sys_kill			sys32_kill
38	i386	rename			sys_rename
39	i386	mkdir			sys_mkdir
40	i386	rmdir			sys_rmdir
41	i386	dup			sys_dup
42	i386	pipe			sys_pipe
43	i386	times			sys_times			compat_sys_times
44	i386	prof
45	i386	brk			sys_brk
46	i386	setgid			sys_setgid16
47	i386	getgid			sys_getgid16
48	i386	signal			sys_signal
49	i386	geteuid			sys_geteuid16
50	i386	getegid			sys_getegid16
51	i386	acct			sys_acct
52	i386	umount2			sys_umount
53	i386	lock
54	i386	ioctl			sys_ioctl			compat_sys_ioctl
55	i386	fcntl			sys_fcntl			compat_sys_fcntl64
56	i386	mpx
57	i386	setpgid			sys_setpgid
58	i386	ulimit
59	i386	oldolduname		sys_olduname
60	i386	umask			sys_umask
61	i386	chroot			sys_chroot
62	i386	ustat			sys_ustat			compat_sys_ustat
63	i386	dup2			sys_dup2
64	i386	getppid			sys_getppid
65	i386	getpgrp			sys_getpgrp
66	i386	setsid			sys_setsid
67	i386	sigaction		sys_sigaction			sys32_sigaction
68	i386	sgetmask		sys_sgetmask
69	i386	ssetmask		sys_ssetmask
70	i386	setreuid		sys_setreuid16
71	i386	setregid		sys_setregid16
72	i386	sigsuspend		sys_sigsuspend			sys32_sigsuspend
73	i386	sigpending		sys_sigpending			compat_sys_sigpending
74	i386	sethostname		sys_sethostname
75	i386	setrlimit		sys_setrlimit			compat_sys_setrlimit
76	i386	getrlimit		sys_old_getrlimit		compat_sys_old_getrlimit
77	i386	getrusage		sys_getrusage			compat_sys_getrusage
78	i386	gettimeofday		sys_gettimeofday		compat_sys_gettimeofday
79	i386	settimeofday		sys_settimeofday		compat_sys_settimeofday
80	i386	getgroups		sys_getgroups16
81	i386	setgroups		sys_setgroups16
82	i386	select			sys_old_select			compat_sys_old_select
83	i386	symlink			sys_symlink
84	i386	oldlstat		sys_lstat
85	i386	readlink		sys_readlink
86	i386	uselib			sys_uselib
87	i386	swapon			sys_swapon
88	i386	reboot			sys_reboot
89	i386	readdir			sys_old_readdir			compat_sys_old_readdir
90	i386	mmap			sys_old_mmap			sys32_mmap
91	i386	munmap			sys_munmap
92	i386	truncate		sys_truncate
93	i386	ftruncate		sys_ftruncate
94	i386	fchmod			sys_fchmod
95	i386	fchown			sys_fchown16
96	i386	getpriority		sys_getpriority
97	i386	setpriority		sys_setpriority
98	i386	profil
99	i386	statfs			sys_statfs			compat_sys_statfs
100	i386	fstatfs			sys_fstatfs			compat_sys_fstatfs
101	i386	ioperm			sys_ioperm
102	i386	socketcall		sys_socketcall			compat_sys_socketcall
103	i386	syslog			sys_syslog
104	i386	setitimer		sys_setitimer			compat_sys_setitimer
105	i386	getitimer		sys_getitimer			compat_sys_getitimer
106	i386	stat			sys_newstat			compat_sys_newstat
107	i386	lstat			sys_newlstat			compat_sys_newlstat
108	i386	fstat			sys_newfstat			compat_sys_newfstat
109	i386	olduname		sys_uname
110	i386	iopl			ptregs_iopl			stub32_iopl
111	i386	vhangup			sys_vhangup
112	i386	idle
113	i386	vm86old			ptregs_vm86old			sys32_vm86_warning
114	i386	wait4			sys_wait4			compat_sys_wait4
115	i386	swapoff			sys_swapoff
116	i386	sysinfo			sys_sysinfo			compat_sys_sysinfo
117	i386	ipc			sys_ipc				sys32_ipc
118	i386	fsync			sys_fsync
119	i386	sigreturn		ptregs_sigreturn		stub32_sigreturn
120	i386	clone			ptregs_clone			stub32_clone
121	i386	setdomainname		sys_setdomainname
122	i386	uname			sys_newuname
123	i386	modify_ldt		sys_modify_ldt
124	i386	adjtimex		sys_adjtimex			compat_sys_adjtimex
125	i386	mprotect		sys_mprotect			sys32_mprotect
126	i386	sigprocmask		sys_sigprocmask			compat_sys_sigprocmask
127	i386	create_module
128	i386	init_module		sys_init_module
129	i386	delete_module		sys_delete_module
130	i386	get_kernel_syms
131	i386	quotactl		sys_quotactl			sys32_quotactl
132	i386	getpgid			sys_getpgid
133	i386	fchdir			sys_fchdir
134	i386	bdflush			sys_bdflush
135	i386	sysfs			sys_sysfs
136	i386	personality		sys_personality
137	i386	afs_syscall
138	i386	setfsuid		sys_setfsuid16
139	i386	setfsgid		sys_setfsgid16
140	i386	_llseek			sys_llseek
141	i386	getdents		sys_getdents			compat_sys_getdents
142	i386	_newselect		sys_select			compat_sys_select
143	i386	flock			sys_flock
144	i386	msync			sys_msync
145	i386	readv			sys_readv			compat_sys_readv
146	i386	writev			sys_writev			compat_sys_writev
147	i386	getsid			sys_getsid
148	i386	fdatasync		sys_fdatasync
149	i386	_sysctl			sys_sysctl			compat_sys_sysctl
150	i386	mlock			sys_mlock
151	i386	munlock			sys_munlock
152	i386	mlockall		sys_mlockall
153	i386	munlockall		sys_munlockall
154	i386	sched_setparam		sys_sched_setparam
155	i386	sched_getparam		sys_sched_getparam
156	i386	sched_setscheduler	sys_sched_setscheduler
157	i386	sched_getscheduler	sys_sched_getscheduler
158	i386	sched_yield		sys_sched_yield
159	i386	sched_get_priority_max	sys_sched_get_priority_max
160	i386	sched_get_priority_min	sys_sched_get_priority_min
161	i386	sched_rr_get_interval	sys_sched_rr_get_interval	sys32_sched_rr_get_interval
162	i386	nanosleep		sys_nanosleep			compat_sys_nanosleep
163	i386	mremap			sys_mremap
164	i386	setresuid		sys_setresuid16
165	i386	getresuid		sys_getresuid16
166	i386	vm86			ptregs_vm86			sys32_vm86_warning
167	i386	query_module
168	i386	poll			sys_poll
169	i386	nfsservctl
170	i386	setresgid		sys_setresgid16
171	i386	getresgid		sys_getresgid16
172	i386	prctl			sys_prctl
173	i386	rt_sigreturn		ptregs_rt_sigreturn		stub32_rt_sigreturn
174	i386	rt_sigaction		sys_rt_sigaction		sys32_rt_sigaction
175	i386	rt_sigprocmask		sys_rt_sigprocmask
176	i386	rt_sigpending		sys_rt_sigpending		sys32_rt_sigpending
177	i386	rt_sigtimedwait		sys_rt_sigtimedwait		compat_sys_rt_sigtimedwait
178	i386	rt_sigqueueinfo		sys_rt_sigqueueinfo		sys32_rt_sigqueueinfo
179	i386	rt_sigsuspend		sys_rt_sigsuspend
180	i386	pread64			sys_pread64			sys32_pread
181	i386	pwrite64		sys_pwrite64			sys32_pwrite
182	i386	chown			sys_chown16
183	i386	getcwd			sys_getcwd
184	i386	capget			sys_capget
185	i386	capset			sys_capset
186	i386	sigaltstack		ptregs_sigaltstack		stub32_sigaltstack
187	i386	sendfile		sys_sendfile			sys32_sendfile
188	i386	getpmsg
189	i386	putpmsg
190	i386	vfork			ptregs_vfork			stub32_vfork
191	i386	ugetrlimit		sys_getrlimit			compat_sys_getrlimit
192	i386	mmap2			sys_mmap_pgoff
193	i386	truncate64		sys_truncate64			sys32_truncate64
194	i386	ftruncate64		sys_ftruncate64			sys32_ftruncate64
195	i386	stat64			sys_stat64			sys32_stat64
196	i386	lstat64			sys_lstat64			sys32_lstat64
197	i386	fstat64			sys_fstat64			sys32_fstat64
198	i386	lchown32		sys_lchown
199	i386	getuid32		sys_getuid
200	i386	getgid32		sys_getgid
201	i386	geteuid32		sys_geteuid
202	i386	getegid32		sys_getegid
203	i386	setreuid32		sys_setreuid
204	i386	setregid32		sys_setregid
205	i386	getgroups32		sys_getgroups
206	i386	setgroups32		sys_setgroups
207	i386	fchown32		sys_fchown
208	i386	setresuid32		sys_setresuid
209	i386	getresuid32		sys_getresuid
210	i386	setresgid32		sys_setresgid
211	i386	getresgid32		sys_getresgid
212	i386	chown32			sys_chown
213	i386	setuid32		sys_setuid
214	i386	setgid32		sys_setgid
215	i386	setfsuid32		sys_setfsuid
216	i386	setfsgid32		sys_setfsgid
217	i386	pivot_root		sys_pivot_root
218	i386	mincore			sys_mincore
219	i386	madvise			sys_madvise
220	i386	getdents64		sys_getdents64			compat_sys_getdents64
221	i386	fcntl64			sys_fcntl64			compat_sys_fcntl64
# 222 is unused
# 223 is unused
224	i386	gettid			sys_gettid
225	i386	readahead		sys_readahead			sys32_readahead
226	i386	setxattr		sys_setxattr
227	i386	lsetxattr		sys_lsetxattr
228	i386	fsetxattr		sys_fsetxattr
229	i386	getxattr		sys_getxattr
230	i386	lgetxattr		sys_lgetxattr
231	i386	fgetxattr		sys_fgetxattr
232	i386	listxattr		sys_listxattr
233	i386	llistxattr		sys_llistxattr
234	i386	flistxattr		sys_flistxattr
235	i386	removexattr		sys_removexattr
236	i386	lremovexattr		sys_lremovexattr
237	i386	fremovexattr		sys_fremovexattr
238	i386	tkill			sys_tkill
239	i386	sendfile64		sys_sendfile64
240	i386	futex			sys_futex			compat_sys_futex
241	i386	sched_setaffinity	sys_sched_setaffinity		compat_sys_sched_setaffinity
242	i386	sched_getaffinity	sys_sched_getaffinity		compat_sys_sched_getaffinity
243	i386	set_thread_area		sys_set_thread_area
244	i386	get_thread_area		sys_get_thread_area
245	i386	io_setup		sys_io_setup			compat_sys_io_setup
246	i386	io_destroy		sys_io_destroy
247	i386	io_getevents		sys_io_getevents		compat_sys_io_getevents
248	i386	io_submit		sys_io_submit			compat_sys_io_submit
249	i386	io_cancel		sys_io_cancel
250	i386	fadvise64		sys_fadvise64			sys32_fadvise64
# 251 is available for reuse (was briefly sys_set_zone_reclaim)
252	i386	exit_group		sys_exit_group
253	i386	lookup_dcookie		sys_lookup_dcookie		sys32_lookup_dcookie
254	i386	epoll_create		sys_epoll_create
255	i386	epoll_ctl		sys_epoll_ctl
256	i386	epoll_wait		sys_epoll_wait
257	i386	remap_file_pages	sys_remap_file_pages
258	i386	set_tid_address		sys_set_tid_address
259	i386	timer_create		sys_timer_create		compat_sys_timer_create
260	i386	timer_settime		sys_timer_settime		compat_sys_timer_settime
261	i386	timer_gettime		sys_timer_gettime		compat_sys_timer_gettime
262	i386	timer_getoverrun	sys_timer_getoverrun
263	i386	timer_delete		sys_timer_delete
264	i386	clock_settime		sys_clock_settime		compat_sys_clock_settime
265	i386	clock_gettime		sys_clock_gettime		compat_sys_clock_gettime
266	i386	clock_getres		sys_clock_getres		compat_sys_clock_getres
267	i386	clock_nanosleep		sys_clock_nanosleep		compat_sys_clock_nanosleep
268	i386	statfs64		sys_statfs64			compat_sys_statfs64
269	i386	fstatfs64		sys_fstatfs64			compat_sys_fstatfs64
270	i386	tgkill			sys_tgkill
271	i386	utimes			sys_utimes			compat_sys_utimes
272	i386	fadvise64_64		sys_fadvise64_64		sys32_fadvise64_64
273	i386	vserver
274	i386	mbind			sys_mbind
275	i386	get_mempolicy		sys_get_mempolicy		compat_sys_get_mempolicy
276	i386	set_mempolicy		sys_set_mempolicy
277	i386	mq_open			sys_mq_open			compat_sys_mq_open
278	i386	mq_unlink		sys_mq_unlink
279	i386	mq_timedsend		sys_mq_timedsend		compat_sys_mq_timedsend
280	i386	mq_timedreceive		sys_mq_timedreceive		compat_sys_mq_timedreceive
281	i386	mq_notify		sys_mq_notify			compat_sys_mq_notify
282	i386	mq_getsetattr		sys_mq_getsetattr		compat_sys_mq_getsetattr
283	i386	kexec_load		sys_kexec_load			compat_sys_kexec_load
284	i386	waitid			sys_waitid			compat_sys_waitid
# 285 sys_setaltroot
286	i386	add_key			sys_add_key
287	i386	request_key		sys_request_key
288	i386	keyctl			sys_keyctl
289	i386	ioprio_set		sys_ioprio_set
290	i386	ioprio_get		sys_ioprio_get
291	i386	inotify_init		sys_inotify_init
292	i386	inotify_add_watch	sys_inotify_add_watch
293	i386	inotify_rm_watch	sys_inotify_rm_watch
294	i386	migrate_pages		sys_migrate_pages
295	i386	openat			sys_openat			compat_sys_openat
296	i386	mkdirat			sys_mkdirat
297	i386	mknodat			sys_mknodat
298	i386	fchownat		sys_fchownat
299	i386	futimesat		sys_futimesat			compat_sys_futimesat
300	i386	fstatat64		sys_fstatat64			sys32_fstatat
301	i386	unlinkat		sys_unlinkat
302	i386	renameat		sys_renameat
303	i386	linkat			sys_linkat
304	i386	symlinkat		sys_symlinkat
305	i386	readlinkat		sys_readlinkat
306	i386	fchmodat		sys_fchmodat
307	i386	faccessat		sys_faccessat
308	i386	pselect6		sys_pselect6			compat_sys_pselect6
309	i386	ppoll			sys_ppoll			compat_sys_ppoll
310	i386	unshare			sys_unshare
311	i386	set_robust_list		sys_set_robust_list		compat_sys_set_robust_list
312	i386	get_robust_list		sys_get_robust_list		compat_sys_get_robust_list
313	i386	splice			sys_splice
314	i386	sync_file_range		sys_sync_file_range		sys32_sync_file_range
315	i386	tee			sys_tee
316	i386	vmsplice		sys_vmsplice			compat_sys_vmsplice
317	i386	move_pages		sys_move_pages			compat_sys_move_pages
318	i386	getcpu			sys_getcpu
319	i386	epoll_pwait		sys_epoll_pwait
320	i386	utimensat		sys_utimensat			compat_sys_utimensat
321	i386	signalfd		sys_signalfd			compat_sys_signalfd
322	i386	timerfd_create		sys_timerfd_create
323	i386	eventfd			sys_eventfd
324	i386	fallocate		sys_fallocate			sys32_fallocate
325	i386	timerfd_settime		sys_timerfd_settime		compat_sys_timerfd_settime
326	i386	timerfd_gettime		sys_timerfd_gettime		compat_sys_timerfd_gettime
327	i386	signalfd4		sys_signalfd4			compat_sys_signalfd4
328	i386	eventfd2		sys_eventfd2
329	i386	epoll_create1		sys_epoll_create1
330	i386	dup3			sys_dup3
331	i386	pipe2			sys_pipe2
332	i386	inotify_init1		sys_inotify_init1
333	i386	preadv			sys_preadv			compat_sys_preadv
334	i386	pwritev			sys_pwritev			compat_sys_pwritev
335	i386	rt_tgsigqueueinfo	sys_rt_tgsigqueueinfo		compat_sys_rt_tgsigqueueinfo
336	i386	perf_event_open		sys_perf_event_open
337	i386	recvmmsg		sys_recvmmsg			compat_sys_recvmmsg
338	i386	fanotify_init		sys_fanotify_init
339	i386	fanotify_mark		sys_fanotify_mark		sys32_fanotify_mark
340	i386	prlimit64		sys_prlimit64
341	i386	name_to_handle_at	sys_name_to_handle_at
342	i386	open_by_handle_at	sys_open_by_handle_at		compat_sys_open_by_handle_at
343	i386	clock_adjtime		sys_clock_adjtime		compat_sys_clock_adjtime
344	i386	syncfs			sys_syncfs
345	i386	sendmmsg		sys_sendmmsg			compat_sys_sendmmsg
346	i386	setns			sys_setns
347	i386	process_vm_readv	sys_process_vm_readv		compat_sys_process_vm_readv
348	i386	process_vm_writev	sys_process_vm_writev		compat_sys_process_vm_writev
349	i386	kcmp			sys_kcmp