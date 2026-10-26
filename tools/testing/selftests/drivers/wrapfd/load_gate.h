/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2026 Google LLC.
 *
 * Holds a WRAPFD_DEV_IOC_LOAD in flight inside the driver, so that a test can probe the wrap
 * while the LOAD is in progress.
 *
 * The LOAD is held by an unsignaled sw_sync fence in the dma-buf's reservation object. LOAD calls
 * dma_buf_begin_cpu_access() after the driver has marked the wrap as in use (or taken the wrap's
 * lock), and before it reads the source file; that call waits interruptibly for the fence.
 * Signaling the fence lets the LOAD continue. While the fence is unsignaled, every CPU access to
 * the dma-buf that waits for fences waits for it too, such as another LOAD or
 * DMA_BUF_IOCTL_SYNC; reads through an existing mapping do not.
 *
 * Only load_gate_hold(), load_gate_wait_held() and load_gate_release() know how the LOAD is held.
 * The probes run one call on another thread while the LOAD is held, and tell whether that call
 * returned while the LOAD was held or blocked inside the driver. The held LOAD runs as a probe
 * too.
 */
#ifndef __WRAPFD_LOAD_GATE_H
#define __WRAPFD_LOAD_GATE_H

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <linux/dma-buf.h>
#include <linux/types.h>
#include <linux/wrapfd.h>

/* From drivers/dma-buf/sw_sync.c; not in a uapi header. */
struct sw_sync_create_fence_data {
	__u32 value;
	char name[32];
	__s32 fence;
};

#define SW_SYNC_IOC_MAGIC		'W'
#define SW_SYNC_IOC_CREATE_FENCE	\
	_IOWR(SW_SYNC_IOC_MAGIC, 0, struct sw_sync_create_fence_data)
#define SW_SYNC_IOC_INC			_IOW(SW_SYNC_IOC_MAGIC, 1, __u32)

/* For C libraries whose uapi headers predate it. */
#ifndef DMA_BUF_IOCTL_IMPORT_SYNC_FILE
struct dma_buf_import_sync_file {
	__u32 flags;
	__s32 fd;
};

#define DMA_BUF_IOCTL_IMPORT_SYNC_FILE	_IOW(DMA_BUF_BASE, 3, struct dma_buf_import_sync_file)
#endif

#define LOAD_GATE_DEBUGFS	"/sys/kernel/debug"
#define LOAD_GATE_SW_SYNC	LOAD_GATE_DEBUGFS "/sync/sw_sync"

/* How long load_gate_wait_held() waits for the LOAD to be held, in milliseconds. */
#define LOAD_GATE_WAIT_MS	10000

/* How long probe_settle() waits for a probe to return or block, in milliseconds. */
#define PROBE_WAIT_MS		1000

/* Reads up to @size - 1 bytes of @path into @buf. Returns the number of bytes read, or -1. */
static ssize_t load_gate_read_file(const char *path, char *buf, size_t size)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n >= 0)
		buf[n] = '\0';
	return n;
}

/*
 * Reads the system call that thread @tid of this process is blocked in, with its first two
 * arguments. Returns false if the thread is running or not in a system call.
 */
static bool task_syscall(pid_t tid, long *nr, unsigned long *arg0, unsigned long *arg1)
{
	char path[64], buf[256];

	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
	if (load_gate_read_file(path, buf, sizeof(buf)) <= 0)
		return false;
	return sscanf(buf, "%ld %lx %lx", nr, arg0, arg1) == 3 && *nr >= 0;
}

/* Returns the scheduler state ('R', 'S', 'D', ...) of thread @tid of this process, or 0. */
static char task_state(pid_t tid)
{
	char path[64], buf[512], *p;

	snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
	if (load_gate_read_file(path, buf, sizeof(buf)) <= 0)
		return 0;
	/* The state follows the command name, which may contain spaces and parentheses. */
	p = strrchr(buf, ')');
	return p && p[1] == ' ' ? p[2] : 0;
}

/*
 * Returns the scheduler state of thread @tid of this process if it is blocked inside
 * ioctl(@fd, @cmd), or inside any ioctl on @fd if @cmd is 0; returns 0 otherwise. The system call
 * is read before and after the state, so a thread that leaves the ioctl in between does not count.
 */
static char task_ioctl_state(pid_t tid, int fd, unsigned int cmd)
{
	unsigned long arg0, arg1, arg0_after, arg1_after;
	long nr, nr_after;
	char state;

	if (!task_syscall(tid, &nr, &arg0, &arg1))
		return 0;
	state = task_state(tid);
	if (!task_syscall(tid, &nr_after, &arg0_after, &arg1_after))
		return 0;
	if (nr != __NR_ioctl || nr_after != nr || arg0_after != arg0 || arg1_after != arg1)
		return 0;
	if (arg0 != (unsigned long)fd || (cmd && (unsigned int)arg1 != cmd))
		return 0;
	return state;
}

enum probe_outcome {
	PROBE_RETURNED,	/* returned while the LOAD was held */
	PROBE_BLOCKED,	/* blocked inside the driver while the LOAD was held */
	PROBE_RUNNING,	/* neither, after PROBE_WAIT_MS */
};

struct probe {
	void *(*fn)(void *arg);	/* returns its int result as its exit value */
	void *arg;
	int wrapfd;		/* the wrap the call operates on */
	pthread_t thread;
	pid_t tid;		/* the probe's thread id, set by the probe thread */
	int done;		/* set by the probe thread once the call returned */
	int ret;		/* the call's result */
};

static void *probe_main(void *arg)
{
	struct probe *probe = arg;

	__atomic_store_n(&probe->tid, (pid_t)syscall(__NR_gettid), __ATOMIC_RELEASE);
	probe->ret = (int)(intptr_t)probe->fn(probe->arg);
	__atomic_store_n(&probe->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

/*
 * Starts @fn(@arg) on a new thread. @fn returns its int result as its exit value, cast to
 * void * through intptr_t. @wrapfd is the wrap the call operates on. Returns 0, or -errno.
 */
static int probe_start(struct probe *probe, void *(*fn)(void *), int wrapfd, void *arg)
{
	memset(probe, 0, sizeof(*probe));
	probe->fn = fn;
	probe->wrapfd = wrapfd;
	probe->arg = arg;
	return -pthread_create(&probe->thread, NULL, probe_main, probe);
}

/*
 * Waits until the probe has returned, or is blocked inside an ioctl on its wrap, or PROBE_WAIT_MS
 * have passed. A block must be seen three times in a row, so that a passing sleep does not count.
 */
static enum probe_outcome probe_settle(struct probe *probe)
{
	int blocked = 0;

	for (int ms = 0; ms < PROBE_WAIT_MS; ms++) {
		pid_t tid = __atomic_load_n(&probe->tid, __ATOMIC_ACQUIRE);
		char state;

		if (__atomic_load_n(&probe->done, __ATOMIC_ACQUIRE))
			return PROBE_RETURNED;
		state = tid ? task_ioctl_state(tid, probe->wrapfd, 0) : 0;
		blocked = state == 'D' || state == 'S' ? blocked + 1 : 0;
		if (blocked == 3)
			return PROBE_BLOCKED;
		usleep(1000);
	}
	return PROBE_RUNNING;
}

/* Waits for the probe thread and returns the call's result. */
static int probe_join(struct probe *probe)
{
	pthread_join(probe->thread, NULL);
	return probe->ret;
}

struct load_gate {
	int timeline_fd;	/* sw_sync timeline */
	int fence_fd;		/* sync_file of the fence that holds the LOAD */
	struct wrapfd_load load;
	struct probe loader;	/* runs the held LOAD */
	bool started;
};

/* The loader's call. Returns the LOAD's result, 0 or -errno, as its exit value. */
static void *load_gate_load(void *arg)
{
	struct load_gate *gate = arg;
	int ret = ioctl(gate->loader.wrapfd, WRAPFD_DEV_IOC_LOAD, &gate->load);

	return (void *)(intptr_t)(ret < 0 ? -errno : ret);
}

/*
 * Opens the sw_sync timeline. If debugfs is not mounted, mounts it first, in a mount namespace of
 * this process's own, so that nothing stays mounted once the test process is gone. Returns the
 * fd, or -errno; -ENODEV if the kernel has no sw_sync, or no debugfs to reach it through.
 */
static int load_gate_open_timeline(void)
{
	int fd;

	fd = open(LOAD_GATE_SW_SYNC, O_RDWR | O_CLOEXEC);
	if (fd >= 0)
		return fd;
	if (errno != ENOENT)
		return -errno;
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return -errno;
	/* No mount point: the kernel has no debugfs, or does not allow mounting it. */
	if (mount("debugfs", LOAD_GATE_DEBUGFS, "debugfs", 0, NULL))
		return errno == ENOENT ? -ENODEV : -errno;
	fd = open(LOAD_GATE_SW_SYNC, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? -ENODEV : -errno;
	return fd;
}

static void load_gate_close(struct load_gate *gate)
{
	if (gate->fence_fd >= 0)
		close(gate->fence_fd);
	if (gate->timeline_fd >= 0)
		close(gate->timeline_fd);
	gate->fence_fd = -1;
	gate->timeline_fd = -1;
}

/*
 * Starts a LOAD of @len bytes at @file_offs of @file_fd into @wrapfd at @buf_offs, on a new
 * thread, and holds it inside the driver until load_gate_release(). The fence is imported
 * through @wrapfd, which forwards the ioctl to its dma-buf. Call it before the test process
 * starts any thread of its own: it may have to unshare the mount namespace. Returns 0, or
 * -errno; -ENODEV if the kernel cannot hold a LOAD this way.
 */
static int load_gate_hold(struct load_gate *gate, int wrapfd, int file_fd,
			  __u64 file_offs, __u64 buf_offs, __u64 len)
{
	struct sw_sync_create_fence_data create = { .value = 1, .name = "wrapfd_load_gate" };
	struct dma_buf_import_sync_file import = { .flags = DMA_BUF_SYNC_WRITE };
	int ret;

	memset(gate, 0, sizeof(*gate));
	gate->fence_fd = -1;
	gate->timeline_fd = load_gate_open_timeline();
	if (gate->timeline_fd < 0)
		return gate->timeline_fd;
	if (ioctl(gate->timeline_fd, SW_SYNC_IOC_CREATE_FENCE, &create)) {
		ret = -errno;
		goto err;
	}
	gate->fence_fd = create.fence;

	/* A write fence: both CPU reads and CPU writes of the dma-buf wait for it. */
	import.fd = gate->fence_fd;
	if (ioctl(wrapfd, DMA_BUF_IOCTL_IMPORT_SYNC_FILE, &import)) {
		ret = errno == ENOTTY ? -ENODEV : -errno;
		goto err;
	}

	gate->load = (struct wrapfd_load){
		.fd = file_fd,
		.file_offs = file_offs,
		.buf_offs = buf_offs,
		.len = len,
	};
	ret = probe_start(&gate->loader, load_gate_load, wrapfd, gate);
	if (ret)
		goto err;
	gate->started = true;
	return 0;

err:
	/* Closing the timeline signals the fence, so the dma-buf is not left gated. */
	load_gate_close(gate);
	return ret;
}

/*
 * Waits until the held LOAD is blocked inside the driver. Returns 0, -ETIMEDOUT, or -EALREADY if
 * the LOAD returned without being held.
 */
static int load_gate_wait_held(struct load_gate *gate)
{
	for (int ms = 0; ms < LOAD_GATE_WAIT_MS; ms++) {
		pid_t tid = __atomic_load_n(&gate->loader.tid, __ATOMIC_ACQUIRE);

		if (__atomic_load_n(&gate->loader.done, __ATOMIC_ACQUIRE))
			return -EALREADY;
		/*
		 * Inside LOAD, the fence wait is the only interruptible sleep: the wrap's lock, the
		 * reservation lock and the wait for the read all sleep uninterruptibly ('D').
		 */
		if (tid && task_ioctl_state(tid, gate->loader.wrapfd, WRAPFD_DEV_IOC_LOAD) == 'S')
			return 0;
		usleep(1000);
	}
	return -ETIMEDOUT;
}

/* Signals the fence, waits for the loader, and returns the LOAD's result: 0 or -errno. */
static int load_gate_release(struct load_gate *gate)
{
	__u32 one = 1;
	int ret = 0;

	if (gate->timeline_fd >= 0 && ioctl(gate->timeline_fd, SW_SYNC_IOC_INC, &one))
		ret = -errno;
	/* Closing the timeline also signals the fence, should the increment have failed. */
	load_gate_close(gate);
	if (gate->started) {
		int load_ret = probe_join(&gate->loader);

		gate->started = false;
		if (!ret)
			ret = load_ret;
	}
	return ret;
}

#endif /* __WRAPFD_LOAD_GATE_H */
