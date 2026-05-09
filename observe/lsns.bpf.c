// SPDX-License-Identifier: GPL-2.0

#include <sys/cdefs.h>
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define NS_MAP_MAX 4096

/* task/thread helpers and state constants (keep in sync with proc-info.bpf.c)
 */
#define PF_KTHREAD 0x00200000
#define EXIT_DEAD 0x00000010
#define EXIT_ZOMBIE 0x00000020
#define thread_leader_only(task)                                               \
	do                                                                         \
	{                                                                          \
		if (task->pid != task->tgid)                                           \
			return 0;                                                          \
	} while (0)
#define skip_kthread(task)                                                     \
	do                                                                         \
	{                                                                          \
		if (task->flags & PF_KTHREAD)                                          \
			return 0;                                                          \
	} while (0)

enum ns_type_t
{
	NS_USER = 1,
	NS_IPC,
	NS_MNT,
	NS_PID,
	NS_NET,
	NS_UTS,
	NS_TIME,
	NS_CGROUP,
	NS_PID_FOR_CHILDREN,
};

struct ns_key_t
{
	u32 type;
	u64 inum;
};

struct ns_owner_t
{
	u32 pid; /* tgid */
	u32 uid;
	u32 procs;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ns_key_t);
	__type(value, struct ns_owner_t);
	__uint(max_entries, NS_MAP_MAX);
} ns_map SEC(".maps");

/* per-CPU counters for namespace instances to avoid cross-CPU RMW races */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct ns_key_t);
	__type(value, u32);
	__uint(max_entries, NS_MAP_MAX);
} ns_cnt_map SEC(".maps");

static char LICENSE[] SEC("license") = "GPL";

static __always_inline int is_user_task(struct task_struct *task)
{
	if (!task)
	{
		return 0;
	}
	/* skip exiting / zombie */
	if (BPF_CORE_READ(task, exit_state) & (EXIT_DEAD | EXIT_ZOMBIE))
	{
		return 0;
	}
	return 1;
}

static __always_inline void
record_ns(const struct ns_key_t *key, struct ns_owner_t *cur_owner)
{
	if (!key || !key->inum)
	{
		return;
	}
	struct ns_owner_t *exist = bpf_map_lookup_elem(&ns_map, key);
	if (!exist)
	{
		/* first seen for this namespace instance */
		cur_owner->procs = 1;
		bpf_map_update_elem(&ns_map, key, cur_owner, BPF_NOEXIST);
	}
	else
	{
		/* copy existing value, increment procs and possibly update owner */
		struct ns_owner_t tmp = {};
		tmp.pid = exist->pid;
		tmp.uid = exist->uid;
		tmp.procs = exist->procs + 1;
		if (cur_owner->pid < exist->pid)
		{
			tmp.pid = cur_owner->pid;
			tmp.uid = cur_owner->uid;
		}
		bpf_map_update_elem(&ns_map, key, &tmp, BPF_ANY);
	}
}
#define MAX_SEEN 12
static __always_inline int seen_check_and_add(
	struct ns_key_t *seen,
	int *seen_cnt,
	const struct ns_key_t *k
)
{
	int i;
#pragma unroll
	for (i = 0; i < MAX_SEEN; i++)
	{
		if (i >= *seen_cnt)
		{
			break;
		}
		if (seen[i].type == k->type && seen[i].inum == k->inum)
		{
			return 1;
		}
	}
	if (*seen_cnt < MAX_SEEN)
	{
		seen[*seen_cnt] = *k;
		(*seen_cnt)++;
	}
	return 0;
}

SEC("iter/task")
int iter_tasks(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	if (!task)
	{
		return 0;
	}

	/* only consider tasks that represent active user-space thread group leaders
	 */
	if (!is_user_task(task))
	{
		return 0;
	}
	/* only handle thread group leaders (one entry per process) */
	if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
	{
		return 0;
	}

	struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
	struct ns_key_t key = {};
	struct ns_owner_t cur_owner = {};
	/* owner = current task's tgid and uid */
	cur_owner.pid = BPF_CORE_READ(task, tgid);
	cur_owner.uid = BPF_CORE_READ(task, real_cred, uid.val);
	struct ns_key_t seen[MAX_SEEN];
	int seen_cnt = 0;

	/* user namespace from task->cred->user_ns */
	struct user_namespace *user_ns = BPF_CORE_READ(task, cred, user_ns);
	if (user_ns)
	{
		key.type = NS_USER;
		key.inum = BPF_CORE_READ(user_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	if (!nsproxy)
	{
		return 0;
	}

	struct uts_namespace *uts_ns = BPF_CORE_READ(nsproxy, uts_ns);
	if (uts_ns)
	{
		key.type = NS_UTS;
		key.inum = BPF_CORE_READ(uts_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct ipc_namespace *ipc_ns = BPF_CORE_READ(nsproxy, ipc_ns);
	if (ipc_ns)
	{
		key.type = NS_IPC;
		key.inum = BPF_CORE_READ(ipc_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
	if (mnt_ns)
	{
		key.type = NS_MNT;
		key.inum = BPF_CORE_READ(mnt_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
	if (pid_ns)
	{
		key.type = NS_PID_FOR_CHILDREN;
		key.inum = BPF_CORE_READ(pid_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	/* There are places where pid namespace is stored elsewhere; try to read
	 * task thread_pid if exists */
	if (bpf_core_field_exists(task->thread_pid))
	{
		struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
		if (thread_pid)
		{
			/* try to get pid namespace from upid->ns */
			if (bpf_core_field_exists(thread_pid->level))
			{
				unsigned int level = BPF_CORE_READ(thread_pid, level);
				if ((int)level >= 0)
				{
					struct upid *upid =
						(struct upid *)&thread_pid->numbers[level];
					if (bpf_core_field_exists(upid->ns))
					{
						struct pid_namespace *pns = BPF_CORE_READ(upid, ns);
						if (pns)
						{
							key.type = NS_PID;
							key.inum = BPF_CORE_READ(pns, ns.inum);
							if (key.inum)
							{
								if (!seen_check_and_add(seen, &seen_cnt, &key))
								{
									record_ns(&key, &cur_owner);
								}
							}
						}
					}
				}
			}
		}
	}

	struct net *net_ns = BPF_CORE_READ(nsproxy, net_ns);
	if (net_ns)
	{
		key.type = NS_NET;
		key.inum = BPF_CORE_READ(net_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct time_namespace *time_ns = BPF_CORE_READ(nsproxy, time_ns);
	if (time_ns)
	{
		key.type = NS_TIME;
		key.inum = BPF_CORE_READ(time_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct time_namespace *time_ns_for_children =
		BPF_CORE_READ(nsproxy, time_ns_for_children);
	if (time_ns_for_children)
	{
		key.type = NS_TIME; /* treat same as time */
		key.inum = BPF_CORE_READ(time_ns_for_children, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	struct cgroup_namespace *cgroup_ns = BPF_CORE_READ(nsproxy, cgroup_ns);
	if (cgroup_ns)
	{
		key.type = NS_CGROUP;
		key.inum = BPF_CORE_READ(cgroup_ns, ns.inum);
		if (key.inum)
		{
			if (!seen_check_and_add(seen, &seen_cnt, &key))
			{
				record_ns(&key, &cur_owner);
			}
		}
	}

	return 0;
}
