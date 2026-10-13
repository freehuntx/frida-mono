import { onUnload } from '../runtime/cleanup'
import { keepAlive } from './keep-alive'

/**
 * Callbacks that stay safe to call after the script unloads.
 *
 * Some Mono registrations can't be undone (`mono_install_assembly_load_hook` has no "uninstall"). A
 * plain `NativeCallback` is freed with the script, so the runtime would later jump into freed memory.
 * Instead, Mono gets the address of a tiny trampoline in memory the script doesn't own (mmap /
 * VirtualAlloc, never freed). It jumps through a slot that points to the `NativeCallback` while the
 * script is loaded; on unload, the slot is switched to a stub that returns 0.
 *
 * The leak is a few bytes per callback per script load, which is fine for registrations made once.
 */

const STUB_SIZE = 32
const SLOT_SIZE = Process.pointerSize

interface Pages {
  code: NativePointer
  slots: NativePointer
  returnZero: NativePointer
  used: number
  capacity: number
}

let pages: Pages | null = null
const liveSlots: { slot: NativePointer; returnZero: NativePointer }[] = []

function allocatePermanent(size: number): NativePointer {
  if (Process.platform === 'windows') {
    const virtualAlloc = new NativeFunction(Module.getGlobalExportByName('VirtualAlloc'), 'pointer', ['pointer', 'size_t', 'uint32', 'uint32'], 'win64')
    const MEM_COMMIT_RESERVE = 0x3000
    const PAGE_READWRITE = 0x04
    const address = virtualAlloc(NULL, size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    if (address.isNull()) throw new Error('VirtualAlloc failed')
    return address
  }
  const mmap = new NativeFunction(Module.getGlobalExportByName('mmap'), 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'int64'])
  const PROT_READ_WRITE = 0x3
  const MAP_PRIVATE_ANONYMOUS = Process.platform === 'darwin' ? 0x1002 : 0x22
  const address = mmap(NULL, size, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, -1, 0)
  if (address.equals(ptr(-1))) throw new Error('mmap failed')
  return address
}

function writeReturnZero(code: NativePointer): void {
  switch (Process.arch) {
    case 'x64':
    case 'ia32': {
      const w = new X86Writer(code)
      w.putXorRegReg('eax', 'eax')
      w.putRet()
      w.flush()
      break
    }
    case 'arm64': {
      const w = new Arm64Writer(code)
      w.putLdrRegU64('x0', 0)
      w.putRet()
      w.flush()
      break
    }
    default:
      throw new Error(`Persistent callbacks are not implemented for ${Process.arch}`)
  }
}

function writeTrampoline(code: NativePointer, slot: NativePointer): void {
  switch (Process.arch) {
    case 'x64': {
      // rax is free at function entry in both SysV and Win64 (only `al` matters for varargs calls).
      const w = new X86Writer(code)
      w.putMovRegAddress('rax', slot)
      w.putJmpRegOffsetPtr('rax', 0)
      w.flush()
      break
    }
    case 'ia32': {
      const w = new X86Writer(code)
      w.putJmpNearPtr(slot)
      w.flush()
      break
    }
    case 'arm64': {
      // x16 (IP0) is the intra-procedure-call scratch register.
      const w = new Arm64Writer(code)
      w.putLdrRegAddress('x16', slot)
      w.putLdrRegRegOffset('x16', 'x16', 0)
      w.putBrReg('x16')
      w.flush()
      break
    }
    default:
      throw new Error(`Persistent callbacks are not implemented for ${Process.arch}`)
  }
}

function getPages(): Pages {
  if (pages !== null && pages.used < pages.capacity) return pages

  const size = Process.pageSize
  const code = allocatePermanent(size)
  const slots = allocatePermanent(size)
  writeReturnZero(code)
  pages = { code, slots, returnZero: code, used: 0, capacity: Math.min(size / STUB_SIZE - 1, size / SLOT_SIZE) }
  return pages
}

/**
 * Like `new NativeCallback(fn, ret, args)`, but the returned address remains callable (as a no-op
 * returning 0) after the script is unloaded.
 */
export function persistentCallback(fn: AnyFunction, ret: NativeCallbackReturnType, args: NativeCallbackArgumentType[], abi?: NativeABI): NativePointer {
  const impl = fn as unknown as NativeCallbackImplementation<NativeCallbackReturnValue, NativeCallbackArgumentValue[]>
  const callback = abi === undefined ? new NativeCallback(impl, ret, args) : new NativeCallback(impl, ret, args, abi)
  keepAlive(callback)

  const p = getPages()
  const index = p.used++
  const slot = p.slots.add(index * SLOT_SIZE)
  const stub = p.code.add((index + 1) * STUB_SIZE)
  slot.writePointer(callback)

  Memory.protect(p.code, Process.pageSize, 'rw-')
  writeTrampoline(stub, slot)
  Memory.protect(p.code, Process.pageSize, 'r-x')

  if (liveSlots.length === 0) {
    onUnload(() => {
      for (const { slot: s, returnZero } of liveSlots) s.writePointer(returnZero)
      liveSlots.length = 0
    })
  }
  liveSlots.push({ slot, returnZero: p.returnZero })
  return stub
}

type AnyFunction = (...args: never[]) => unknown
