/* eslint-disable no-undef */
/*
 * Frida agent — POSIX (Linux / macOS).
 *
 * Observe-only in M4. Hooks libc/libSystem `execve`, `openat`, and `connect`
 * and posts a JSON message back to the Node loader on every call. Never
 * calls Interceptor.replace, never blocks the syscall.
 *
 * Loader configures which targets to hook via `recv('configure', ...)`.
 */

"use strict";

const TARGET_HANDLERS = {
  execve: hookExecve,
  openat: hookOpenat,
  connect: hookConnect,
};

const TARGET_HANDLERS_ENFORCE = {
  execve: hookExecveEnforce,
  openat: hookOpenatEnforce,
  // connect enforce intentionally not implemented in M4.5 — return-value
  // rewriting on connect needs sockaddr decoding and is deferred.
  connect: hookConnect,
};

const installed = [];
let enforceMode = false;
let requestSeq = 0;

function hookExecve() {
  const sym = Module.findExportByName(null, "execve");
  if (!sym) return false;
  Interceptor.attach(sym, {
    onEnter(args) {
      try {
        const path = readCString(args[0]);
        const argv = readCStringArray(args[1]);
        post({
          kind: "syscall",
          syscall: "execve",
          pid: Process.id,
          ts: Date.now(),
          argv: argv,
          path: path,
        });
      } catch (e) {
        postError("execve.onEnter", e);
      }
    },
  });
  // Also hook posix_spawn on darwin — Node uses this for child processes.
  const spawnSym = Module.findExportByName(null, "posix_spawn");
  if (spawnSym) {
    Interceptor.attach(spawnSym, {
      onEnter(args) {
        try {
          const path = readCString(args[1]);
          const argv = readCStringArray(args[3]);
          post({
            kind: "syscall",
            syscall: "execve",
            pid: Process.id,
            ts: Date.now(),
            argv: argv,
            path: path,
            extra: { via: "posix_spawn" },
          });
        } catch (e) {
          postError("posix_spawn.onEnter", e);
        }
      },
    });
  }
  return true;
}

function hookOpenat() {
  // On darwin, Node often goes through plain `open` rather than `openat`.
  // Hook both when available; treat either as an "openat" syscall event.
  let any = false;
  const tryHook = function (name, pathArgIdx) {
    const sym = Module.findExportByName(null, name);
    if (!sym) return;
    Interceptor.attach(sym, {
      onEnter(args) {
        try {
          const path = readCString(args[pathArgIdx]);
          post({
            kind: "syscall",
            syscall: "openat",
            pid: Process.id,
            ts: Date.now(),
            path: path,
            extra: { via: name },
          });
        } catch (e) {
          postError(name + ".onEnter", e);
        }
      },
    });
    any = true;
  };
  tryHook("openat", 1);
  tryHook("open", 0);
  return any;
}

function nextRequestId() {
  requestSeq = (requestSeq + 1) | 0;
  return "req-" + Process.id + "-" + requestSeq;
}

/**
 * Block-and-decide: post a decision_request with the captured args, wait
 * synchronously for the matching decision_response, and return true to
 * deny / false to allow. The loader is responsible for enforcing a timeout
 * and replying allow on fail-open.
 */
function decide(payload) {
  const id = nextRequestId();
  let decision = "allow";
  const op = recv("decision_response_" + id, (msg) => {
    if (msg && msg.decision === "deny") decision = "deny";
  });
  send(Object.assign({ kind: "decision_request", id: id }, payload));
  try {
    op.wait();
  } catch (e) {
    postError("decide.wait", e);
  }
  return decision === "deny";
}

function hookExecveEnforce() {
  const sym = Module.findExportByName(null, "execve");
  if (!sym) return false;
  Interceptor.replace(
    sym,
    new NativeCallback(
      function (pathPtr, argvPtr, envpPtr) {
        try {
          const pathStr = readCString(pathPtr);
          const argv = readCStringArray(argvPtr);
          const deny = decide({
            syscall: "execve",
            pid: Process.id,
            path: pathStr,
            argv: argv,
          });
          if (deny) {
            // -1 with errno set is the libc-level "permission denied" pattern.
            // setError is provided by Frida; not all runtimes have it, so guard.
            try { if (typeof setError === "function") setError(13); } catch (e) {}
            return -1;
          }
        } catch (e) {
          postError("execveEnforce.replace", e);
        }
        // Fall through to the real libc execve via NativeFunction.
        const orig = new NativeFunction(sym, "int", ["pointer", "pointer", "pointer"]);
        return orig(pathPtr, argvPtr, envpPtr);
      },
      "int",
      ["pointer", "pointer", "pointer"],
    ),
  );
  return true;
}

function hookOpenatEnforce() {
  const sym = Module.findExportByName(null, "openat");
  if (!sym) return false;
  Interceptor.replace(
    sym,
    new NativeCallback(
      function (dirfd, pathPtr, flags, mode) {
        try {
          const pathStr = readCString(pathPtr);
          const deny = decide({
            syscall: "openat",
            pid: Process.id,
            path: pathStr,
          });
          if (deny) {
            try { if (typeof setError === "function") setError(13); } catch (e) {}
            return -1;
          }
        } catch (e) {
          postError("openatEnforce.replace", e);
        }
        const orig = new NativeFunction(sym, "int", ["int", "pointer", "int", "int"]);
        return orig(dirfd, pathPtr, flags, mode);
      },
      "int",
      ["int", "pointer", "int", "int"],
    ),
  );
  return true;
}

function hookConnect() {
  const sym = Module.findExportByName(null, "connect");
  if (!sym) return false;
  Interceptor.attach(sym, {
    onEnter(args) {
      try {
        const sockaddrPtr = args[1];
        post({
          kind: "syscall",
          syscall: "connect",
          pid: Process.id,
          ts: Date.now(),
          addr: sockaddrPtr.toString(),
        });
      } catch (e) {
        postError("connect.onEnter", e);
      }
    },
  });
  return true;
}

function readCString(ptr) {
  if (!ptr || ptr.isNull()) return undefined;
  try {
    return Memory.readUtf8String(ptr);
  } catch (e) {
    return undefined;
  }
}

function readCStringArray(ptr) {
  if (!ptr || ptr.isNull()) return undefined;
  const out = [];
  let cursor = ptr;
  for (let i = 0; i < 64; i++) {
    const elem = Memory.readPointer(cursor);
    if (elem.isNull()) break;
    const s = readCString(elem);
    if (s === undefined) break;
    out.push(s);
    cursor = cursor.add(Process.pointerSize);
  }
  return out;
}

function post(msg) {
  try {
    send(msg);
  } catch (e) {
    /* send() failures are unrecoverable from inside the agent */
  }
}

function postError(where, err) {
  post({
    kind: "error",
    where: where,
    message: err && err.message ? err.message : String(err),
  });
}

recv("configure", (msg) => {
  enforceMode = msg && msg.mode === "enforce";
  const handlers = enforceMode ? TARGET_HANDLERS_ENFORCE : TARGET_HANDLERS;
  const targets = Array.isArray(msg.targets) && msg.targets.length > 0
    ? msg.targets
    : Object.keys(handlers);
  for (const t of targets) {
    const handler = handlers[t];
    if (typeof handler !== "function") continue;
    try {
      if (handler()) installed.push(t);
    } catch (e) {
      postError("install." + t, e);
    }
  }
  post({ kind: "ready", hookedTargets: installed });
});
