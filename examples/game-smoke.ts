// First check against a real game: which Mono, which of the exports the library relies on are there,
// and every class of Assembly-CSharp with its members.
//
//   npm run build:agent examples/game-smoke.ts --watch
//   frida -H 127.0.0.1 -n <Game>.exe -l .build/game-smoke.js

import Mono, { enumMembers, findMonoModule, MONO_API_TABLE, type Class, type Method } from "../src";

// Exports where Mono versions differ, plus a few every version should have.
const PROBES = [
  "mono_thread_attach",
  "mono_runtime_invoke",
  "mono_compile_method",
  "mono_method_get_unmanaged_thunk",
  "mono_profiler_create",
  "mono_profiler_install",
];

// Only classes whose full name contains this are listed ("" = all).
const FILTER = "";

// Every line also goes to this file on the target, flushed right away, so the last step before a
// crash survives it (console output still in flight is lost when the process dies).
const LOG_PATH = `${Process.getTmpDir()}${Process.platform === "windows" ? "\\" : "/"}frida-mono-smoke.log`;
const logFile = new File(LOG_PATH, "w");

function log(line: string): void {
  console.log(line);
  logFile.write(`${line}\n`);
  logFile.flush();
}

function kindOf(klass: Class): string {
  if (klass.isEnum) return "enum";
  if (klass.isValueType) return "struct";
  if (klass.isInterface) return "interface";
  if (klass.isDelegate) return "delegate";
  if (klass.isAbstract && klass.isSealed) return "static class";
  if (klass.isAbstract) return "abstract class";
  if (klass.isSealed) return "sealed class";
  return "class";
}

function signatureOf(method: Method): string {
  const params = method.parameters
    .map((p) => `${p.out ? "out " : p.byRef ? "ref " : ""}${p.type.name} ${p.name}`)
    .join(", ");
  const modifiers = [
    method.access,
    method.isStatic ? "static" : "",
    method.isAbstract ? "abstract" : method.isVirtual ? "virtual" : "",
  ].filter((m) => m !== "");
  const ret = method.isConstructor ? "" : `${method.returnType.name} `;
  return `${modifiers.join(" ")} ${ret}${method.name}(${params})`;
}

// Runs `fn`, turning a throw into a log line, so one broken class doesn't stop the walk.
function attempt(label: string, fn: () => void): void {
  try {
    fn();
  } catch (e) {
    log(`    !! ${label}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function describeClass(klass: Class): void {
  const header = [`${kindOf(klass)} ${klass.fullName}`];
  if (klass.parent !== null && !klass.isEnum && !klass.isValueType) header.push(`: ${klass.parent.fullName}`);
  log(header.join(" "));

  attempt("info", () => {
    const details = [`token 0x${klass.token.toString(16)}`];
    if (klass.declaringClass !== null) details.push(`nested in ${klass.declaringClass.fullName}`);
    if (klass.isGenericDefinition) details.push("generic definition");
    if (!klass.isInterface) details.push(klass.isValueType ? `${klass.valueSize} bytes` : `instance size ${klass.instanceSize}`);
    if (klass.interfaces.length > 0) details.push(`implements ${klass.interfaces.map((i) => i.fullName).join(", ")}`);
    log(`  ${details.join(" | ")}`);
  });

  if (klass.isEnum) {
    attempt("enum values", () => {
      for (const [name, value] of enumMembers(klass)) log(`  ${name} = ${value}`);
    });
    return;
  }

  attempt("fields", () => {
    for (const field of klass.fields) {
      const modifiers = [field.access, field.isStatic ? "static" : "", field.isLiteral ? "const" : "", field.isInitOnly ? "readonly" : ""]
        .filter((m) => m !== "")
        .join(" ");
      const offset = field.isStatic ? "" : ` @ 0x${field.offset.toString(16)}`;
      log(`  field    ${modifiers} ${field.type.name} ${field.name}${offset}`);
    }
  });

  attempt("properties", () => {
    for (const property of klass.properties) {
      const accessors = [property.getter !== null ? "get;" : "", property.setter !== null ? "set;" : ""].filter((a) => a !== "").join(" ");
      log(`  property ${property.isStatic ? "static " : ""}${property.type.name} ${property.name} { ${accessors} }`);
    }
  });

  attempt("events", () => {
    for (const event of klass.events) {
      log(`  event    ${event.isStatic ? "static " : ""}${event.type?.name ?? "?"} ${event.name}`);
    }
  });

  attempt("methods", () => {
    for (const method of klass.methods) log(`  method   ${signatureOf(method)}`);
  });
}

log(`frida-mono smoke: logging to ${LOG_PATH}`);
log(`${Process.platform}/${Process.arch}, Mono module: ${findMonoModule()?.path ?? "(not loaded yet)"}`);

Mono.perform(
  () => {
    log("runtime ready, thread attached");
    log(`Mono ${Mono.version ?? "(no build info: legacy runtime)"} in ${Mono.module.name} @ ${Mono.module.base}`);
    log(`  capabilities: ${JSON.stringify(Mono.capabilities)}`);
    for (const name of PROBES) {
      log(`  ${Mono.api.has(name) ? "✓" : "✗"} ${name}`);
    }
    // Functions frida-mono knows about (from Mono's headers) that this runtime doesn't export.
    const missing = Object.keys(MONO_API_TABLE).filter((name) => !Mono.api.has(name));
    log(`  ${missing.length} of ${Object.keys(MONO_API_TABLE).length} API functions missing: ${missing.join(", ")}`);
    const assemblies = Mono.assemblies;
    log(`  ${assemblies.length} assemblies: ${assemblies.join(", ")}`);

    // Image.classes includes nested classes, so no recursion is needed.
    const classes = Mono.assembly("Assembly-CSharp").image.classes.filter((c) => c.fullName.includes(FILTER));
    log(`\nAssembly-CSharp: ${classes.length} classes`);
    const counts = new Map<string, number>();
    for (const [index, klass] of classes.entries()) {
      log(`\n[${index + 1}/${classes.length}] ${klass.fullName}`);
      counts.set(kindOf(klass), (counts.get(kindOf(klass)) ?? 0) + 1);
      attempt(klass.fullName, () => describeClass(klass));
    }
    log(`\nDone: ${[...counts].map(([kind, count]) => `${count} ${kind}`).join(", ")}`);
  },
  { waitFor: "Assembly-CSharp" },
).catch((e: unknown) => log(`!! failed: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`));
