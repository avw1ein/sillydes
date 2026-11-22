// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// test_os.h for POSIX systems.

#include "test_os.h"

#include "platform.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/ptrace.h>
#else
#include <sys/prctl.h>
#endif

std::string temp_file_name()
{
  char name[] = "/tmp/sillydes_test_XXXXXX";
  int fd = mkstemp(name);
  if (fd >= 0) close(fd);
  return name;
}

void remove_file(const std::string &name)
{
  unlink(name.c_str());
}

intptr_t silence_stderr()
{
  int saved = dup(STDERR_FILENO);
  int nul = open("/dev/null", O_WRONLY);
  dup2(nul, STDERR_FILENO);
  close(nul);
  return saved;
}

void restore_stderr(intptr_t saved)
{
  dup2((int)saved, STDERR_FILENO);
  close((int)saved);
}

long locked_kb()
{
#ifdef __APPLE__
  // The entries of the address space that mlock has wired.
  mach_vm_address_t at = 0;
  natural_t depth = 0;
  mach_vm_size_t wired = 0;
  for (;;) {
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    mach_vm_size_t size = 0;
    if (mach_vm_region_recurse(mach_task_self(), &at, &size, &depth, (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) break;
    if (info.is_submap) {
      depth++;
      continue;
    }
    if (info.user_wired_count > 0) wired += size;
    at += size;
  }
  return (long)(wired / 1024);
#else
  FILE *f = fopen("/proc/self/status", "r");
  long kb = -1;
  char line[128];
  while (f && fgets(line, sizeof line, f))
    if (sscanf(line, "VmLck: %ld kB", &kb) == 1) break;
  if (f) fclose(f);
  return kb;
#endif
}

long memlock_limit_kb()
{
  rlimit rl;
  if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return 0;
  return rl.rlim_cur == RLIM_INFINITY ? 1L << 40 : (long)(rl.rlim_cur / 1024);
}

std::string make_temp_dir()
{
  const char *base = getenv("TMPDIR");
  std::string tmpl = std::string(base && *base ? base : "/tmp") + "/sillydes_e2e_XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  return mkdtemp(buf.data()) ? std::string(buf.data()) : std::string();
}

bool make_dir(const std::string &name)
{
  return mkdir(name.c_str(), 0700) == 0;
}

bool list_dir(const std::string &dir, std::vector<std::string> &names)
{
  DIR *d = opendir(dir.c_str());
  if (!d) return false;
  names.clear();
  while (dirent *e = readdir(d)) {
    std::string n = e->d_name;
    if (n != "." && n != "..") names.push_back(n);
  }
  closedir(d);
  return true;
}

bool is_directory(const std::string &name)
{
  struct stat st;
  return lstat(name.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool file_exists(const std::string &name)
{
  struct stat st;
  return stat(name.c_str(), &st) == 0;
}

void remove_tree(const std::string &name)
{
  if (is_directory(name)) {
    std::vector<std::string> names;
    if (list_dir(name, names))
      for (const std::string &n : names) remove_tree(name + "/" + n);
    rmdir(name.c_str());
  } else {
    unlink(name.c_str());
  }
}

bool make_hard_link(const std::string &existing, const std::string &link)
{
  return ::link(existing.c_str(), link.c_str()) == 0;
}

bool make_symlink(const std::string &target, const std::string &link)
{
  return symlink(target.c_str(), link.c_str()) == 0;
}

bool can_limit_address_space()
{
  return true;
}

RunResult run_program(const std::string &exe, const std::vector<std::string> &args, const RunOptions &opt)
{
  RunResult r;
  signal(SIGPIPE, SIG_IGN);  // a program that stops reading its input must not kill the test
  int in[2], out[2], err[2];
  if (pipe(in) != 0 || pipe(out) != 0 || pipe(err) != 0) return r;
  std::vector<std::string> argv_s;
  argv_s.push_back(exe);
  argv_s.insert(argv_s.end(), args.begin(), args.end());
  std::vector<char *> argv;
  for (std::string &a : argv_s) argv.push_back(&a[0]);
  argv.push_back(nullptr);
  pid_t pid = fork();
  if (pid < 0) return r;
  if (pid == 0) {
    dup2(in[0], 0);
    dup2(out[1], 1);
    dup2(err[1], 2);
    for (int fd : { in[0], in[1], out[0], out[1], err[0], err[1] }) close(fd);
    for (const std::string &e : opt.env) {
      size_t eq = e.find('=');
      if (eq != std::string::npos) setenv(e.substr(0, eq).c_str(), e.substr(eq + 1).c_str(), 1);
    }
    if (opt.address_space_limit_kb > 0) {
      rlimit rl = { (rlim_t)opt.address_space_limit_kb * 1024, (rlim_t)opt.address_space_limit_kb * 1024 };
#ifdef __APPLE__
      // The kernel may not enforce either limit there; the program reads both before it allocates.
      // RLIMIT_AS can keep dyld from mapping the shared cache, RLIMIT_DATA cannot.
      if (setrlimit(RLIMIT_DATA, &rl) != 0) _exit(126);
#else
      setrlimit(RLIMIT_AS, &rl);
#endif
    }
    execv(exe.c_str(), argv.data());
    _exit(127);
  }
  r.started = true;
  close(in[0]);
  close(out[1]);
  close(err[1]);
  // The input is small (a phrase), far below the size of a pipe: it is written at once.
  for (size_t off = 0; off < opt.stdin_data.size();) {
    ssize_t k = write(in[1], opt.stdin_data.data() + off, opt.stdin_data.size() - off);
    if (k < 0) {
      if (errno == EINTR) continue;
      break;
    }
    off += (size_t)k;
  }
  close(in[1]);
  pollfd fds[2] = { { out[0], POLLIN, 0 }, { err[0], POLLIN, 0 } };
  std::string *dest[2] = { &r.out, &r.err };
  for (int open_fds = 2; open_fds > 0;) {
    if (poll(fds, 2, -1) < 0 && errno != EINTR) break;
    for (int i = 0; i < 2; i++) {
      if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      char buf[4096];
      ssize_t k = read(fds[i].fd, buf, sizeof buf);
      if (k > 0) {
        dest[i]->append(buf, (size_t)k);
      } else if (k == 0 || errno != EINTR) {
        close(fds[i].fd);
        fds[i].fd = -1;
        open_fds--;
      }
    }
  }
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  r.code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  return r;
}

bool can_run_on_terminal() { return true; }

namespace {

long now_ms()
{
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// The program turns the echo off after it has written the prompt; typing before that would show the
// phrase. The line discipline echoes at once, so unlike a Windows console it needs the wait.
void wait_for_echo_off(int master)
{
  for (int i = 0; i < 400; i++) {
    termios t;
    if (tcgetattr(master, &t) == 0 && !(t.c_lflag & ECHO)) return;
    usleep(5000);
  }
}

}  // namespace

TerminalResult run_on_terminal(const std::string &exe, const std::vector<std::string> &args, const std::vector<TypedLine> &lines, int timeout_ms)
{
  TerminalResult r;
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) return r;
  const char *name = ptsname(master);
  if (!name) return r;
  const std::string slave = name;
  std::vector<std::string> argv_s;
  argv_s.push_back(exe);
  argv_s.insert(argv_s.end(), args.begin(), args.end());
  std::vector<char *> argv;
  for (std::string &a : argv_s) argv.push_back(&a[0]);
  argv.push_back(nullptr);
  pid_t pid = fork();
  if (pid < 0) return r;
  if (pid == 0) {
    setsid();
    int s = open(slave.c_str(), O_RDWR);  // the first terminal opened after setsid
    if (s < 0) _exit(126);
    ioctl(s, TIOCSCTTY, 0);
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
    if (s > 2) close(s);
    close(master);
    execv(exe.c_str(), argv.data());
    _exit(127);
  }
  r.started = true;
  const long deadline = now_ms() + timeout_ms;
  size_t next = 0, from = 0;
  for (;;) {
    if (now_ms() > deadline) {
      r.timed_out = true;
      kill(pid, SIGKILL);
      break;
    }
    pollfd p = { master, POLLIN, 0 };
    int k = poll(&p, 1, 50);
    if (k > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR))) {
      char buf[4096];
      ssize_t n = read(master, buf, sizeof buf);
      if (n > 0) r.output.append(buf, (size_t)n);
      else if (n == 0 || errno != EINTR) break;  // the program has gone: EIO on Linux, end of file on macOS
    }
    while (next < lines.size()) {
      size_t at = r.output.find(lines[next].after, from);
      if (at == std::string::npos) break;
      from = at + lines[next].after.size();
      wait_for_echo_off(master);
      const std::string &text = lines[next].text;
      for (size_t off = 0; off < text.size();) {
        ssize_t n = write(master, text.data() + off, text.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        off += (size_t)n;
      }
      next++;
    }
  }
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  if (WIFEXITED(status)) r.code = WEXITSTATUS(status);
  close(master);
  return r;
}

std::string find_program(const std::string &name)
{
  const char *path = getenv("PATH");
  std::string dirs = path ? path : "";
  for (size_t start = 0; start <= dirs.size();) {
    size_t end = dirs.find(':', start);
    if (end == std::string::npos) end = dirs.size();
    std::string candidate = dirs.substr(start, end - start) + "/" + name;
    if (access(candidate.c_str(), X_OK) == 0) return candidate;
    start = end + 1;
  }
  return std::string();
}

#ifdef __APPLE__
// Forks a child (that calls harden_process() first if `hardened`) and has a second process try to
// attach to it as a debugger, which on a process that denies it does not fail at once but blocks:
// 1 if the attach worked, 0 if the system refused it, 2 if it was still blocked after 5 seconds,
// -1 if the experiment did not run.
static int attach_to_child(bool hardened)
{
  int ready[2];
  if (pipe(ready) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) {
    close(ready[0]);
    close(ready[1]);
    return -1;
  }
  if (pid == 0) {
    close(ready[0]);
    if (hardened) harden_process();
    char c = 'x';
    if (write(ready[1], &c, 1) != 1) _exit(1);
    for (;;) pause();
  }
  close(ready[1]);
  char c = 0;
  ssize_t got;
  do got = read(ready[0], &c, 1); while (got < 0 && errno == EINTR);
  close(ready[0]);
  int result = -1;
  pid_t debugger = got == 1 ? fork() : -1;
  if (debugger == 0) {
    const bool attached = ptrace(PT_ATTACHEXC, pid, nullptr, 0) == 0;
    if (attached) ptrace(PT_DETACH, pid, nullptr, 0);
    _exit(attached ? 0 : 1);
  }
  int status = 0;
  if (debugger > 0) {
    pid_t done = 0;
    for (int tries = 0; tries < 100 && (done = waitpid(debugger, &status, WNOHANG)) == 0; tries++) usleep(50000);
    if (done == debugger) result = WIFEXITED(status) ? (WEXITSTATUS(status) == 0 ? 1 : 0) : -1;
    else result = 2;
  }
  // A traced process does not die of SIGKILL until it is let go.
  kill(pid, SIGCONT);
  kill(pid, SIGKILL);
  if (debugger > 0) kill(debugger, SIGKILL);
  for (pid_t p : { pid, debugger })
    for (int tries = 0; p > 0 && tries < 100 && waitpid(p, &status, WNOHANG) == 0; tries++) usleep(50000);
  return result;
}
#endif

int check_hardening(std::string &detail)
{
  rlimit rl;
  if (getrlimit(RLIMIT_CORE, &rl) != 0 || rl.rlim_cur != 0) {
    detail = "core dumps are not switched off (RLIMIT_CORE)";
    return 1;
  }
#ifdef __APPLE__
  // PT_DENY_ATTACH cannot be read back, so try what it prevents: a debugger of the same user attaching
  // to a child that called harden_process, and, as a control, to one that did not.
  const int target = attach_to_child(true), control = attach_to_child(false);
  if (target < 0 || control < 0 || control == 2) {
    detail = "RLIMIT_CORE is 0; the attach experiment could not be run";
    return -1;
  }
  if (target == 1) {
    detail = "RLIMIT_CORE is 0, but a debugger of the same user could attach to a hardened process (PT_DENY_ATTACH)";
    return 1;
  }
  if (control == 0) {
    detail = "RLIMIT_CORE is 0; a debugger could not attach to an ordinary child either (taken from the signature or SIP), so PT_DENY_ATTACH is not shown";
    return -1;
  }
  detail = std::string("RLIMIT_CORE is 0, and a debugger could attach to an ordinary child but ") +
           (target == 2 ? "its attach to a hardened one did not complete" : "not to a hardened one") + " (PT_DENY_ATTACH)";
  return 0;
#else
  if (prctl(PR_GET_DUMPABLE) != 0) {
    detail = "the process is still dumpable (PR_SET_DUMPABLE)";
    return 1;
  }
  detail = "RLIMIT_CORE is 0 and the process is not dumpable";
  return 0;
#endif
}
