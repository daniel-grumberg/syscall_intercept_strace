#include "config.h"

#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

int main(int argc, char *argv[]) {
  std::optional<std::string> OutputFileEnv;
  unsigned CmdStart = 1;
  if (std::string(argv[1]) == "-o") {
    std::string OutputFile("SYSCALL_LOG_PATH=");
    OutputFile += argv[2];
    OutputFileEnv = std::move(OutputFile);
    CmdStart = 3;
  }

  const char *Envp[3];
  Envp[0] = "LD_PRELOAD=" STRACE_PRELOAD_LIB;
  if (OutputFileEnv)
    Envp[1] = OutputFileEnv->c_str();
  else
    Envp[1] = nullptr;
  Envp[2] = nullptr;

  execve(argv[CmdStart], &argv[CmdStart], const_cast<char *const *>(Envp));
  return 0;
}
