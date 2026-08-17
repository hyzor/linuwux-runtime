/*
 * Copyright (C) 2026 brcly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * linuwux -- libc interposition: installs the SIGSEGV/SIGSYS wrappers and
 * chains to whatever Wine originally registered.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"
#include "registry.h"


typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction;
static void (*real_free)(void *);
static _Thread_local void *last_win32u_free;

/* Only sa_sigaction is chained; store it atomically to avoid torn struct copies. */
typedef void (*linuwux_sig_handler_fn)(int, siginfo_t *, void *);
static _Atomic(linuwux_sig_handler_fn) s_real_segv_handler;
static _Atomic(linuwux_sig_handler_fn) s_real_sys_handler;

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx);
static void linuwux_sigsys_wrapper(int sig, siginfo_t *info, void *uctx);

static void linuwux_chain_segv(int sig, siginfo_t *info, void *uctx)
{
    linuwux_sig_handler_fn real = atomic_load(&s_real_segv_handler);
    if (real)
        real(sig, info, uctx);
    else {
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
    }
}

static void linuwux_chain_sigsys(int sig, siginfo_t *info, void *uctx)
{
    linuwux_sig_handler_fn real = atomic_load(&s_real_sys_handler);
    if (real)
        real(sig, info, uctx);
}

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *ctx = (ucontext_t *)uctx;
    if (linuwux_cpuid_spoof(info, ctx))
        return;
    linuwux_chain_segv(sig, info, uctx);
}

static void linuwux_sigsys_wrapper(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *ctx = (ucontext_t *)uctx;
    if (linuwux_sigsys_route(ctx))
        return;
    linuwux_chain_sigsys(sig, info, uctx);
}

/* dlsym(RTLD_NEXT) inside free() crashes during loader startup (before
 * constructors run) when a library is co-preloaded. Resolve up front. */
__attribute__((constructor))
static void linuwux_hooks_resolve_libc(void)
{
    void *libc_handle = dlopen("libc.so.6", RTLD_NOW);
    if (libc_handle) {
        real_free = (void (*)(void *))dlsym(libc_handle, "free");
        real_sigaction = (sigaction_fn)dlsym(libc_handle, "sigaction");
    }
    if (!real_free)
        real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!real_free || !real_sigaction)
        linuwux_log("failed to resolve libc free/sigaction; dropping frees\n");
}

__attribute__((visibility("default")))
void free(void *ptr)
{
    Dl_info caller_info;
    void *caller;
    int from_win32u = 0;

    /* Pre-constructor (loader startup) frees are dropped: resolving here
     * crashes; the few leaked allocations are a one-time cost. */
    if (!real_free)
        return;

    caller = __builtin_return_address(0);
    if (ptr && linuwux_is_game_process() && linuwux_cpuid_legacy_active() &&
        dladdr(caller, &caller_info) && caller_info.dli_fname &&
        strstr(caller_info.dli_fname, "/win32u.so"))
        from_win32u = 1;

    if (from_win32u && last_win32u_free == ptr)
        return;

    if (from_win32u)
        last_win32u_free = ptr;

    real_free(ptr);
}

/* Enable CPUID faults once; TIF_NOCPUID is inherited by new threads on clone. */
static void linuwux_enable_cpuid_fault(void)
{
    static _Atomic int done;
    int expected_done = 0;
    if (!atomic_compare_exchange_strong(&done, &expected_done, 1))
        return;
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
    linuwux_log("CPUID faulting enabled (tid=%d)\n", (int)syscall(SYS_gettid));
}

__attribute__((visibility("default")))
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (!real_sigaction) {
        errno = ENOSYS;
        return -1;
    }

    if (!linuwux_is_game_process())
        return real_sigaction(signum, act, oldact);

    if (act && signum == SIGSEGV && act->sa_sigaction != linuwux_segv_wrapper) {
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_segv_wrapper;
        int r = real_sigaction(signum, &ours, oldact);
        if (r == 0) {
            atomic_store(&s_real_segv_handler, act->sa_sigaction);
            linuwux_log("intercepted Wine's sigaction(SIGSEGV, ...)\n");
            linuwux_enable_cpuid_fault();
            /* Registry I/O is not AS-safe — do this here (normal context,
             * ntdll already mapped), never from the CPUID/SIGSEGV arm path. */
            linuwux_set_hwprofile_guid();
        }
        return r;
    }
    if (act && signum == SIGSYS && act->sa_sigaction != linuwux_sigsys_wrapper) {
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_sigsys_wrapper;
        int r = real_sigaction(signum, &ours, oldact);
        if (r == 0) {
            atomic_store(&s_real_sys_handler, act->sa_sigaction);
            linuwux_log("intercepted Wine's sigaction(SIGSYS, ...)\n");
        }
        return r;
    }
    return real_sigaction(signum, act, oldact);
}
