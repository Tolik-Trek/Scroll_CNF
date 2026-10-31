'use strict';

// Host supplies: globalThis.RUN_ROOT = absolute Windows directory.
// Load while our x86 process is suspended. Resume only after guard_ready.
// This is in-process instrumentation, NOT an operating-system sandbox.
(function () {
  const DENY = -1073741790; // STATUS_ACCESS_DENIED (0xc0000022)
  const NULL = ptr(0);
  let seq = 0;
  let failed = false;
  let expectSplwowChild = false; // armed by a read-only open of *splwow64.exe
  const retained = [];
  const installed = [];
  const internal = new Set();
  const writeMask = 0x530d0116; // generic write/all, maximum/system, delete/DAC/owner, data/EA/attributes

  function emit(record) {
    send(Object.assign({ type: 'guard_event', seq: ++seq, pid: Process.id }, record));
  }
  function error(api, exception) {
    failed = true;
    emit({ type: 'guard_error', api: api, error: String(exception), denied: true });
  }
  function requireExport(module, name) {
    return Process.getModuleByName(module).getExportByName(name);
  }
  function native(module, name, result, args) {
    return new NativeFunction(requireExport(module, name), result, args, 'stdcall');
  }

  try {
    if (Process.platform !== 'windows' || Process.arch !== 'ia32' || Process.pointerSize !== 4)
      throw new Error('Only suspended Windows ia32 process is supported');
    if (typeof globalThis.RUN_ROOT !== 'string' || !globalThis.RUN_ROOT)
      throw new Error('RUN_ROOT must be supplied before this script');

    const CreateFileW = native('kernel32.dll', 'CreateFileW', 'pointer',
      ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']);
    const CloseHandle = native('kernel32.dll', 'CloseHandle', 'int', ['pointer']);
    const GetFinalPath = native('kernel32.dll', 'GetFinalPathNameByHandleW', 'uint32',
      ['pointer', 'pointer', 'uint32', 'uint32']);
    const GetAttributes = new SystemFunction(requireExport('kernel32.dll', 'GetFileAttributesW'),
      'uint32', ['pointer'], 'stdcall');
    const GetHandleInformation = native('kernel32.dll', 'GetFileInformationByHandle', 'int',
      ['pointer', 'pointer']);

    function normalize(input) {
      let value = input.replace(/\//g, '\\');
      if (value.indexOf('\\??\\') === 0 || value.indexOf('\\\\?\\') === 0)
        value = value.substring(4);
      if (!/^[A-Za-z]:\\/.test(value)) throw new Error('Non-DOS absolute path');
      if (value.substring(2).indexOf(':') !== -1) throw new Error('Alternate stream denied');
      if (/[\x00-\x1f]/.test(value)) throw new Error('Control character in path');
      value = value.replace(/\\+$/, '');
      const components = value.substring(3).split('\\');
      if (components.some(function (item) { return !item || item === '.' || item === '..' || /[ .]$/.test(item); }))
        throw new Error('Ambiguous path component');
      return value;
    }
    function finalPath(handle) {
      const buffer = Memory.alloc(65536);
      const count = GetFinalPath(handle, buffer, 32768, 0);
      if (count === 0 || count >= 32768) throw new Error('Cannot resolve handle path');
      return normalize(buffer.readUtf16String(count));
    }
    function guardedInternal(body) {
      const thread = Process.getCurrentThreadId();
      internal.add(thread);
      try { return body(); } finally { internal.delete(thread); }
    }
    function openRead(path) {
      return CreateFileW(Memory.allocUtf16String(path), 0x80, 7, NULL, 3, 0x02000000, NULL);
    }
    function invalidHandle(handle) { return handle.equals(ptr('0xffffffff')) || handle.isNull(); }

    const requestedRoot = normalize(globalThis.RUN_ROOT);
    const rootHandle = openRead(requestedRoot);
    if (invalidHandle(rootHandle)) throw new Error('Cannot open existing RUN_ROOT');
    let root;
    try { root = finalPath(rootHandle); } finally { CloseHandle(rootHandle); }
    const rootLower = root.toLowerCase();
    function inside(path) {
      const lower = path.toLowerCase();
      return lower === rootLower || lower.indexOf(rootLower + '\\') === 0;
    }
    // Reject reparse components and multiple hard links. This precheck is not
    // race-proof against an external actor changing the directory concurrently.
    function safeWritePath(path) {
      path = normalize(path);
      if (!inside(path)) return { allowed: false, path: path, reason: 'outside_run_root' };
      const pieces = path.substring(3).split('\\');
      let partial = path.substring(0, 3);
      let missing = false;
      for (let i = 0; i < pieces.length; i++) {
        partial += (i === 0 ? '' : '\\') + pieces[i];
        const queried = GetAttributes(Memory.allocUtf16String(partial));
        const attributes = queried.value;
        if (attributes === 0xffffffff) {
          const code = queried.lastError;
          if (code !== 2 && code !== 3) throw new Error('Unresolved path attributes: ' + code);
          missing = true;
          break;
        }
        if ((attributes & 0x400) !== 0) return { allowed: false, path: path, reason: 'reparse_component' };
      }
      if (!missing) {
        const check = guardedInternal(function () {
          const handle = openRead(path);
          if (invalidHandle(handle)) throw new Error('Cannot inspect existing write target');
          try {
            const resolved = finalPath(handle);
            const info = Memory.alloc(52);
            if (!GetHandleInformation(handle, info)) throw new Error('Cannot inspect link count');
            return { resolved: resolved, links: info.add(40).readU32() };
          } finally { CloseHandle(handle); }
        });
        if (!inside(check.resolved)) return { allowed: false, path: path, reason: 'resolved_outside_root' };
        if (check.links > 1) return { allowed: false, path: path, reason: 'multiple_hard_links' };
      }
      return { allowed: true, path: path, reason: 'run_root' };
    }
    // x86 OBJECT_ATTRIBUTES: Length@0, RootDirectory@4, ObjectName@8.
    // x86 UNICODE_STRING: Length@0, MaximumLength@2, Buffer@4.
    function objectPath(attributes) {
      if (attributes.isNull() || attributes.readU32() < 24) throw new Error('Invalid OBJECT_ATTRIBUTES');
      const name = attributes.add(8).readPointer();
      if (name.isNull()) throw new Error('Missing object name');
      const length = name.readU16();
      if ((length & 1) || length === 0 || length > name.add(2).readU16()) throw new Error('Invalid UNICODE_STRING');
      const buffer = name.add(4).readPointer();
      if (buffer.isNull()) throw new Error('Null name buffer');
      const value = buffer.readUtf16String(length / 2);
      const directory = attributes.add(4).readPointer();
      if (directory.isNull()) return value;
      if (value[0] === '\\' || /^[A-Za-z]:/.test(value)) throw new Error('RootDirectory with absolute name');
      return finalPath(directory) + '\\' + value;
    }
    function deniedFile(output, iosb) {
      if (!output.isNull()) output.writePointer(NULL);
      if (!iosb.isNull()) { iosb.writeS32(DENY); iosb.add(4).writeU32(0); }
      return DENY;
    }
    function replace(name, args, callback) {
      const address = requireExport('ntdll.dll', name);
      const original = new NativeFunction(address, 'int', args, 'stdcall');
      const replacement = new NativeCallback(function () {
        const values = Array.prototype.slice.call(arguments);
        try { return callback(original, values); }
        catch (exception) { error(name, exception); return DENY; }
      }, 'int', args, 'stdcall');
      retained.push(original, replacement);
      Interceptor.replace(address, replacement);
      installed.push(name);
    }
    function fileOpen(api, original, args, disposition, options) {
      // Only our own read-only path-inspection calls bypass the replacement.
      if (internal.has(Process.getCurrentThreadId())) return original.apply(null, args);
      const desired = args[1] >>> 0;
      const writable = (desired & writeMask) !== 0 || disposition !== 1 || (options & 0x1000) !== 0;
      let path = null;
      let consoleDevice = false;
      let decision = { allowed: !writable, reason: 'read_only' };
      try {
        path = objectPath(args[2]);
        if (path !== null && /\\splwow64\.exe$/i.test(path)) expectSplwowChild = true;
        // Exact DOS device names only, not a directory/path-prefix exemption.
        // Our launcher owns stdio and starts CREATE_NO_WINDOW; these CRT opens
        // may fail naturally, but they must not be classified as disk writes.
        consoleDevice = ['\\??\\CONIN$', '\\??\\CONOUT$', '\\??\\NUL'].indexOf(path.toUpperCase()) !== -1;
        if (consoleDevice) {
          if (failed) decision = { allowed: false, reason: 'previous_guard_error' };
          else if (disposition !== 1 || (options & 0x3000) !== 0)
            decision = { allowed: false, reason: 'console_device_destructive_open' };
          else decision = { allowed: true, reason: 'exact_dos_console_device' };
        } else if (writable) {
          if (failed) decision = { allowed: false, reason: 'previous_guard_error' };
          else if (options & 0x2000) decision = { allowed: false, reason: 'file_by_id' };
          else decision = safeWritePath(path);
        }
      } catch (exception) {
        error(api, exception);
        if (writable) decision = { allowed: false, reason: 'unresolved_write' };
        else decision = { allowed: true, reason: 'unresolved_read' };
      }
      const result = decision.allowed ? original.apply(null, args) : deniedFile(args[0], args[3]);
      emit({ api: api, path: path, mode: consoleDevice ? 'console_device_trace' : (writable ? 'write_capable' : 'read_only'),
        desired_access: desired, disposition: disposition, options: options,
        denied: !decision.allowed, reason: decision.reason, result: result });
      return result;
    }
    replace('NtCreateFile', ['pointer', 'uint32', 'pointer', 'pointer', 'pointer', 'uint32', 'uint32', 'uint32', 'uint32', 'pointer', 'uint32'],
      function (original, args) { return fileOpen('NtCreateFile', original, args, args[7], args[8]); });
    replace('NtOpenFile', ['pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'uint32'],
      function (original, args) { return fileOpen('NtOpenFile', original, args, 1, args[5]); });

    // x86 FILE_RENAME_INFORMATION: RootDirectory@4, FileNameLength@8,
    // FileName@12. Only ordinary class 10 is qualified; other variants deny.
    function renameDestination(buffer, bytes, source) {
      if (buffer.isNull() || bytes < 12) throw new Error('Invalid rename buffer');
      const length = buffer.add(8).readU32();
      if (length === 0 || (length & 1) || length > bytes - 12 || length > 65534)
        throw new Error('Invalid rename name length');
      const name = buffer.add(12).readUtf16String(length / 2);
      if (name.length !== length / 2 || name.indexOf('\x00') !== -1)
        throw new Error('Embedded/truncated rename name');
      const directory = buffer.add(4).readPointer();
      const simple = !/[\\/:]/.test(name);
      if (!directory.isNull()) {
        if (!simple) throw new Error('Rename RootDirectory requires simple relative name');
        return normalize(finalPath(directory) + '\\' + name);
      }
      if (simple) return normalize(source.substring(0, source.lastIndexOf('\\') + 1) + name);
      // No base is invented for a relative name with slashes and NULL root.
      return normalize(name);
    }
    const names = new Set([11, 56, 57, 65, 66, 72, 73]);
    replace('NtSetInformationFile', ['pointer', 'pointer', 'pointer', 'uint32', 'uint32'],
      function (original, args) {
        const kind = args[4];
        let path = null;
        let destination = null;
        let sourceChecked = false;
        let destinationChecked = false;
        let decision;
        if (kind === 10) {
          if (failed) decision = { allowed: false, reason: 'previous_guard_error' };
          else {
            path = finalPath(args[0]);
            const sourceDecision = safeWritePath(path);
            sourceChecked = sourceDecision.allowed;
            if (!sourceChecked) decision = { allowed: false, reason: 'rename_source_' + sourceDecision.reason };
            else {
              destination = renameDestination(args[2], args[3], path);
              const targetDecision = safeWritePath(destination);
              destinationChecked = targetDecision.allowed;
              decision = destinationChecked ? { allowed: true, reason: 'internal_rename' } :
                { allowed: false, reason: 'rename_destination_' + targetDecision.reason };
            }
          }
        } else if (names.has(kind)) decision = { allowed: false, reason: 'rename_or_link' };
        else if (kind === 14) decision = { allowed: true, reason: 'file_position_only' };
        else {
          path = finalPath(args[0]);
          decision = failed ? { allowed: false, reason: 'previous_guard_error' } : safeWritePath(path);
        }
        const result = decision.allowed ? original.apply(null, args) : deniedFile(NULL, args[1]);
        emit({ api: 'NtSetInformationFile', path: path, destination: destination,
          source_checked: sourceChecked, destination_checked: destinationChecked,
          mode: 'file_information', info_class: kind,
          denied: !decision.allowed, reason: decision.reason, result: result });
        return result;
      });

    // Native delete bypasses NtCreateFile on some callers, so guard its OA too.
    replace('NtDeleteFile', ['pointer'], function (original, args) {
      const path = objectPath(args[0]);
      const decision = failed ? { allowed: false, reason: 'previous_guard_error' } : safeWritePath(path);
      const result = decision.allowed ? original.apply(null, args) : DENY;
      emit({ api: 'NtDeleteFile', path: path, mode: 'delete', denied: !decision.allowed,
        reason: decision.reason, result: result });
      return result;
    });

    function denyNative(name, count, mode, required) {
      const module = Process.getModuleByName('ntdll.dll');
      if (module.findExportByName(name) === null) {
        if (required) throw new Error('Required export missing: ' + name);
        emit({ api: name, mode: mode, absent: true, denied: null });
        return;
      }
      replace(name, Array(count).fill('pointer'), function () {
        emit({ api: name, path: null, mode: mode, denied: true, result: DENY });
        return DENY;
      });
    }
    // Legacy CRT/application code may use CreateKey to read an existing key.
    // Replace that request with a strictly read-only OPEN of the same OA.
    // Never invoke native NtCreateKey and never fabricate a missing key.
    const NtOpenKeyReadOnly = native('ntdll.dll', 'NtOpenKey', 'int',
      ['pointer', 'uint32', 'pointer']);
    replace('NtCreateKey', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer'],
      function (_original, args) {
        if (args[0].isNull()) throw new Error('NtCreateKey has null output handle');
        args[0].writePointer(NULL);
        const requested = args[1] >>> 0;
        const effective = 0x20019 | (requested & 0x300); // KEY_READ plus WOW64 view flags only
        const result = failed ? DENY : NtOpenKeyReadOnly(args[0], effective, args[2]);
        if (result >= 0 && !args[6].isNull()) args[6].writeU32(2); // REG_OPENED_EXISTING_KEY
        emit({ api: 'NtCreateKey', path: null, mode: 'registry_readonly_open',
          original_access: requested, effective_access: effective, create_options: args[5],
          native_operation: 'NtOpenKey', denied: failed, creation_permitted: false, result: result });
        return result;
      });
    // An attempted value write is expected from this legacy compiler. It is
    // still denied, never delegated, and never reported as a successful write.
    // The host may continue ONLY for this exact expected-block signature.
    replace('NtSetValueKey', ['pointer', 'pointer', 'uint32', 'uint32', 'pointer', 'uint32'],
      function () {
        emit({ api: 'NtSetValueKey', path: null, mode: 'registry_mutation',
          reason: 'readonly_registry_policy', denied: true, expected_block: true,
          native_executed: false, result: DENY });
        return DENY;
      });
    [ ['NtCreateKeyTransacted', 8],
      ['NtDeleteValueKey', 2], ['NtDeleteKey', 1], ['NtRenameKey', 2],
      ['NtSetInformationKey', 4], ['NtRestoreKey', 3], ['NtReplaceKey', 3],
      ['NtLoadKey', 2], ['NtLoadKey2', 3], ['NtLoadKeyEx', 8],
      ['NtUnloadKey', 1], ['NtUnloadKey2', 2], ['NtUnloadKeyEx', 2],
      ['NtSaveKey', 2], ['NtSaveKeyEx', 3], ['NtSaveMergedKeys', 3]
    ].forEach(function (spec) { denyNative(spec[0], spec[1], 'registry_mutation', true); });
    // Expected Windows thunk: 32-bit maxplus2 may spawn C:\WINDOWS\splwow64.exe
    // to talk to the 64-bit print spooler. Allow that exact image path only;
    // every other child process stays denied. Image name is read from
    // RTL_USER_PROCESS_PARAMETERS.ImagePathName (UNICODE_STRING, x86 offset 0x38).
    replace('NtCreateUserProcess', Array(11).fill('pointer'), function (original, args) {
      let image = null;
      try {
        const params = args[2];
        if (!params.isNull()) {
          image = params.add(0x38 + 4).readPointer().readUtf16String();
        }
      } catch (exception) { image = null; }
      const byImage = image !== null && /\\splwow64\.exe$/i.test(image);
      const byArmedOpen = image === null && expectSplwowChild;
      expectSplwowChild = false; // one-shot
      if (byImage || byArmedOpen) {
        const result = original.apply(null, args);
        emit({ api: 'NtCreateUserProcess', path: image, mode: 'child_process_creation',
          denied: false, reason: byImage ? 'expected_splwow64_thunk' : 'expected_splwow64_by_prior_open', result: result });
        return result;
      }
      emit({ api: 'NtCreateUserProcess', path: image, mode: 'child_process_creation',
        denied: true, reason: 'not_expected_image', result: DENY });
      return DENY;
    });
    [ ['NtCreateProcess', 8], ['NtCreateProcessEx', 9] ]
      .forEach(function (spec) { denyNative(spec[0], spec[1], 'child_process_creation', true); });

    // Values, section names and key names are deliberately never collected.
    [ ['GetPrivateProfileStringA', 5, false], ['GetPrivateProfileStringW', 5, true],
      ['WritePrivateProfileStringA', 3, false], ['WritePrivateProfileStringW', 3, true],
      ['GetPrivateProfileIntA', 3, false], ['GetPrivateProfileIntW', 3, true],
      ['GetPrivateProfileSectionA', 3, false], ['GetPrivateProfileSectionW', 3, true],
      ['WritePrivateProfileSectionA', 2, false], ['WritePrivateProfileSectionW', 2, true]
    ].forEach(function (spec) {
      const address = requireExport('kernel32.dll', spec[0]);
      Interceptor.attach(address, {
        onEnter: function (args) {
          try {
            const value = args[spec[1]];
            this.profilePath = value.isNull() ? null : (spec[2] ? value.readUtf16String() : value.readCString());
          } catch (exception) { error(spec[0], exception); this.profilePath = null; }
        },
        onLeave: function (retval) {
          emit({ api: spec[0], path: this.profilePath, mode: 'profile_api_trace',
            denied: false, result: retval.toInt32() });
        }
      });
      installed.push(spec[0]);
    });
    Interceptor.attach(requireExport('ntdll.dll', 'RtlExitUserProcess'), {
      onEnter: function (args) {
        try { emit({ type: 'guard_exit', api: 'RtlExitUserProcess', status: args[0].toInt32(), failed: failed }); }
        catch (exception) { error('RtlExitUserProcess', exception); }
      }
    });
    installed.push('RtlExitUserProcess');
    Interceptor.flush();
    emit({ type: 'guard_ready', root: root, hooks: installed,
      runtime: Script.runtime, frida: Frida.version, failed: failed });
  } catch (exception) {
    error('guard_install', exception);
    // Deliberately no guard_ready: host must never resume this process.
  }
})();
