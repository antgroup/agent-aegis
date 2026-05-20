/* eslint-disable no-undef */
/*
 * Frida agent — Windows placeholder.
 *
 * Real Windows hook targets would include:
 *   - kernel32!CreateProcessW   (execve equivalent)
 *   - kernel32!CreateFileW       (openat equivalent)
 *   - ws2_32!WSAConnect          (connect equivalent)
 *
 * Implementing these is a follow-on milestone; this file exists so the
 * loader has a stable target path on win32 and adding Windows support is a
 * single-file change.
 */
"use strict";
send({ kind: "unsupported", platform: "win32" });
