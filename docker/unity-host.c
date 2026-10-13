// Embeds a Mono runtime the way a Unity player does: dlopen the runtime library, point it at its
// class libraries, mono_jit_init_version, then run an assembly. Used for the Unity fork e2e targets.
//
//   unity-host <runtime.so> <prefix> <Host.exe>
//
// UNITY_HOST_RUNTIME_VERSION picks the profile (default v4.0.30319; legacy Mono 2.6 players use v2.0.50727).
// UNITY_HOST_WAIT_FILE makes it wait until that file exists before loading Mono at all, so a test can
// attach first and watch the runtime load (Mono.perform waiting for the module, init and assemblies).
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef void *(*jit_init_version_fn)(const char *, const char *);
typedef void (*set_dirs_fn)(const char *, const char *);
typedef void (*config_parse_fn)(const char *);
typedef void *(*assembly_open_fn)(void *, const char *);
typedef int (*jit_exec_fn)(void *, void *, int, char **);

static void *sym(void *lib, const char *name) {
  void *f = dlsym(lib, name);
  if (f == NULL) {
    fprintf(stderr, "missing %s\n", name);
    exit(2);
  }
  return f;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <runtime.so> <prefix> <assembly.exe> [args]\n", argv[0]);
    return 2;
  }
  const char *wait_file = getenv("UNITY_HOST_WAIT_FILE");
  if (wait_file != NULL) {
    printf("WAITING\n");
    fflush(stdout);
    while (access(wait_file, F_OK) != 0) usleep(10000);
  }
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
  if (lib == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  char libdir[4096], etcdir[4096];
  snprintf(libdir, sizeof libdir, "%s/lib", argv[2]);
  snprintf(etcdir, sizeof etcdir, "%s/etc", argv[2]);
  ((set_dirs_fn)sym(lib, "mono_set_dirs"))(libdir, etcdir);
  ((config_parse_fn)sym(lib, "mono_config_parse"))(NULL);
  const char *version = getenv("UNITY_HOST_RUNTIME_VERSION");
  void *domain = ((jit_init_version_fn)sym(lib, "mono_jit_init_version"))("Unity Root Domain", version != NULL ? version : "v4.0.30319");
  void *assembly = ((assembly_open_fn)sym(lib, "mono_domain_assembly_open"))(domain, argv[3]);
  if (assembly == NULL) {
    fprintf(stderr, "could not open %s\n", argv[3]);
    return 2;
  }
  return ((jit_exec_fn)sym(lib, "mono_jit_exec"))(domain, assembly, argc - 3, argv + 3);
}
