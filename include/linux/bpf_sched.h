/* SPDX-License-Identifier: GPL-2.0 */
//new-add 1
#ifndef _LINUX_BPF_SCHED_H
#define _LINUX_BPF_SCHED_H

#include <linux/bpf.h>
//new-end 1
#ifdef CONFIG_BPF_SCHED
//new-add 3
#include <linux/jump_label.h>
//new-end 3
//new-add 1
#define BPF_SCHED_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_sched_##NAME(__VA_ARGS__);
#include <linux/sched_hook_defs.h>
#undef BPF_SCHED_HOOK

int bpf_sched_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog);
//new-end 1
//new-add 3
DECLARE_STATIC_KEY_FALSE(bpf_sched_enabled_key);

static inline bool bpf_sched_enabled(void)
{
	return static_branch_unlikely(&bpf_sched_enabled_key);
}

static inline void bpf_sched_inc(void)
{
	static_branch_inc(&bpf_sched_enabled_key);
}

static inline void bpf_sched_dec(void)
{
	static_branch_dec(&bpf_sched_enabled_key);
}
//new-end 3
#else /* !CONFIG_BPF_SCHED */

static inline int bpf_sched_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}
//new-add 3
static inline bool bpf_sched_enabled(void)
{
	return false;
}
//new-end 3
//new-add 1
#endif /* CONFIG_BPF_SCHED */
#endif /* _LINUX_BPF_SCHED_H */
//new-end 1