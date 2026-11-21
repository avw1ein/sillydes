// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// test_os.h for POSIX systems.

#include "test_os.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
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
#ifdef __linux__
  return true;
#else
  return false;  // macOS does not enforce RLIMIT_AS
#endif
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
#ifdef __linux__
    if (opt.address_space_limit_kb > 0) {
      rlimit rl = { (rlim_t)opt.address_space_limit_kb * 1024, (rlim_t)opt.address_space_limit_kb * 1024 };
      setrlimit(RLIMIT_AS, &rl);
    }
#endif
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
