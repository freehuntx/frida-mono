// Frida provides a console in every script, but @types/frida-gum doesn't declare it.
declare const console: {
  log(...data: unknown[]): void
  warn(...data: unknown[]): void
  error(...data: unknown[]): void
}
