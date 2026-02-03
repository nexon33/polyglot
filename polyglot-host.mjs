#!/usr/bin/env node
/**
 * Polyglot Host — Node.js runtime for Polyglot WASM modules
 * 
 * Provides filesystem, environment, console, process, networking,
 * HTTP, async, and streams that bridge WASM to Node.js capabilities.
 * 
 * Usage: node polyglot-host.mjs <path-to-wasm> [args...]
 */

import fs from 'fs';
import path from 'path';
import net from 'net';
import http from 'http';
import https from 'https';
import { execSync, spawnSync } from 'child_process';
import readline from 'readline';
import { URL, fileURLToPath } from 'url';
import { Worker } from 'worker_threads';

// ============================================================================
// Worker Thread for Async Operations
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Shared buffers for worker communication
const SIGNAL_BUFFER_SIZE = 4;
const DATA_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB for large responses

let signalBuffer = null;
let dataBuffer = null;
let signal = null;
let data = null;
let worker = null;

// Signal states
const IDLE = 0;
const REQUEST_PENDING = 1;
const RESPONSE_READY = 2;

function initWorker() {
  try {
    signalBuffer = new SharedArrayBuffer(SIGNAL_BUFFER_SIZE);
    dataBuffer = new SharedArrayBuffer(DATA_BUFFER_SIZE);
    signal = new Int32Array(signalBuffer);
    data = new Uint8Array(dataBuffer);
    
    const workerPath = path.join(__dirname, 'polyglot-host-worker.mjs');
    if (!fs.existsSync(workerPath)) {
      console.log('[host] Worker file not found, async operations will use fallback');
      return false;
    }
    
    worker = new Worker(workerPath, {
      workerData: { signalBuffer, dataBuffer }
    });
    
    worker.on('error', (err) => {
      console.error('[host] Worker error:', err.message);
    });
    
    worker.on('exit', (code) => {
      if (code !== 0) {
        console.error(`[host] Worker exited with code ${code}`);
      }
      worker = null;
    });
    
    console.log('[host] Async worker initialized');
    return true;
  } catch (err) {
    console.log('[host] Worker init failed:', err.message);
    return false;
  }
}

// Synchronous RPC to worker
function workerCall(op, args) {
  if (!worker) {
    return { ok: false, error: 'Worker not available' };
  }
  
  try {
    // Write request to shared buffer
    const request = JSON.stringify({ op, args });
    const encoded = new TextEncoder().encode(request);
    const view = new DataView(dataBuffer);
    view.setUint32(0, encoded.length, true);
    data.set(encoded, 4);
    
    // Signal request pending
    Atomics.store(signal, 0, REQUEST_PENDING);
    Atomics.notify(signal, 0);
    
    // Wait for response
    const waitResult = Atomics.wait(signal, 0, REQUEST_PENDING, 120000); // 2 min timeout
    
    if (waitResult === 'timed-out') {
      Atomics.store(signal, 0, IDLE);
      return { ok: false, error: 'Worker timeout' };
    }
    
    // Read response
    const respLen = view.getUint32(0, true);
    const respBytes = data.subarray(4, 4 + respLen);
    const respJson = new TextDecoder().decode(respBytes);
    
    // Reset signal
    Atomics.store(signal, 0, IDLE);
    
    return JSON.parse(respJson);
  } catch (err) {
    Atomics.store(signal, 0, IDLE);
    return { ok: false, error: err.message };
  }
}

// ============================================================================
// Memory Management
// ============================================================================

let wasmMemory = null;
let wasmInstance = null;

// Allocator for returning data to WASM
// Uses a simple bump allocator in the WASM linear memory
let heapBase = 0;
let heapOffset = 0;

function initHeap(memory) {
  wasmMemory = memory;
  // Start heap after initial 64KB (reserved for stack/static data)
  heapBase = 65536;
  heapOffset = 0;
}

function hostAlloc(size) {
  const ptr = heapBase + heapOffset;
  heapOffset += size;
  // Align to 8 bytes
  heapOffset = (heapOffset + 7) & ~7;
  return ptr;
}

function hostFree(ptr, size) {
  // Simple bump allocator doesn't actually free
  // For production, use a proper allocator
}

// Decode string from WASM memory
function decodeString(ptr, len) {
  const bytes = new Uint8Array(wasmMemory.buffer, ptr, len);
  return new TextDecoder().decode(bytes);
}

// Encode string into WASM memory, return [ptr, len]
function encodeString(str) {
  const bytes = new TextEncoder().encode(str);
  const ptr = hostAlloc(bytes.length);
  new Uint8Array(wasmMemory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

// Write bytes to WASM memory at ptr
function writeBytes(ptr, data) {
  new Uint8Array(wasmMemory.buffer, ptr, data.length).set(data);
}

// Write a usize (32-bit on wasm32) to memory
function writeUsize(ptr, value) {
  new Uint32Array(wasmMemory.buffer, ptr, 1)[0] = value;
}

// Write a pointer to memory
function writePtr(ptr, value) {
  new Uint32Array(wasmMemory.buffer, ptr, 1)[0] = value;
}

// ============================================================================
// Filesystem Imports
// ============================================================================

function host_fs_read(pathPtr, pathLen, outLenPtr) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    const data = fs.readFileSync(filePath);
    const ptr = hostAlloc(data.length);
    writeBytes(ptr, data);
    writeUsize(outLenPtr, data.length);
    return ptr;
  } catch (e) {
    console.error(`[host] fs_read error: ${e.message}`);
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_fs_write(pathPtr, pathLen, dataPtr, dataLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    const data = new Uint8Array(wasmMemory.buffer, dataPtr, dataLen);
    fs.writeFileSync(filePath, data);
    return 0;
  } catch (e) {
    console.error(`[host] fs_write error: ${e.message}`);
    return -1;
  }
}

function host_fs_append(pathPtr, pathLen, dataPtr, dataLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    const data = new Uint8Array(wasmMemory.buffer, dataPtr, dataLen);
    fs.appendFileSync(filePath, data);
    return 0;
  } catch (e) {
    console.error(`[host] fs_append error: ${e.message}`);
    return -1;
  }
}

function host_fs_exists(pathPtr, pathLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    return fs.existsSync(filePath) ? 1 : 0;
  } catch (e) {
    return 0;
  }
}

function host_fs_is_dir(pathPtr, pathLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    return fs.statSync(filePath).isDirectory() ? 1 : 0;
  } catch (e) {
    return 0;
  }
}

function host_fs_mkdir(pathPtr, pathLen) {
  try {
    const dirPath = decodeString(pathPtr, pathLen);
    fs.mkdirSync(dirPath, { recursive: true });
    return 0;
  } catch (e) {
    console.error(`[host] fs_mkdir error: ${e.message}`);
    return -1;
  }
}

function host_fs_remove(pathPtr, pathLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    fs.unlinkSync(filePath);
    return 0;
  } catch (e) {
    console.error(`[host] fs_remove error: ${e.message}`);
    return -1;
  }
}

function host_fs_rmdir(pathPtr, pathLen) {
  try {
    const dirPath = decodeString(pathPtr, pathLen);
    fs.rmSync(dirPath, { recursive: true, force: true });
    return 0;
  } catch (e) {
    console.error(`[host] fs_rmdir error: ${e.message}`);
    return -1;
  }
}

function host_fs_readdir(pathPtr, pathLen, outLenPtr) {
  try {
    const dirPath = decodeString(pathPtr, pathLen);
    const entries = fs.readdirSync(dirPath);
    const json = JSON.stringify(entries);
    const [ptr, len] = encodeString(json);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    console.error(`[host] fs_readdir error: ${e.message}`);
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

// ============================================================================
// Extended Filesystem Imports
// ============================================================================

function host_fs_stat(pathPtr, pathLen, outLenPtr) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    const stat = fs.statSync(filePath);
    const result = {
      size: stat.size,
      mtime: Math.floor(stat.mtimeMs),
      atime: Math.floor(stat.atimeMs),
      ctime: Math.floor(stat.ctimeMs),
      isFile: stat.isFile(),
      isDir: stat.isDirectory(),
      isSymlink: stat.isSymbolicLink(),
      mode: stat.mode,
    };
    const json = JSON.stringify(result);
    const [ptr, len] = encodeString(json);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    console.error(`[host] fs_stat error: ${e.message}`);
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_fs_rename(oldPtr, oldLen, newPtr, newLen) {
  try {
    const oldPath = decodeString(oldPtr, oldLen);
    const newPath = decodeString(newPtr, newLen);
    fs.renameSync(oldPath, newPath);
    return 0;
  } catch (e) {
    console.error(`[host] fs_rename error: ${e.message}`);
    return -1;
  }
}

function host_fs_copy(srcPtr, srcLen, dstPtr, dstLen) {
  try {
    const srcPath = decodeString(srcPtr, srcLen);
    const dstPath = decodeString(dstPtr, dstLen);
    fs.copyFileSync(srcPath, dstPath);
    return 0;
  } catch (e) {
    console.error(`[host] fs_copy error: ${e.message}`);
    return -1;
  }
}

function host_fs_symlink(targetPtr, targetLen, linkPtr, linkLen) {
  try {
    const target = decodeString(targetPtr, targetLen);
    const linkPath = decodeString(linkPtr, linkLen);
    fs.symlinkSync(target, linkPath);
    return 0;
  } catch (e) {
    console.error(`[host] fs_symlink error: ${e.message}`);
    return -1;
  }
}

function host_fs_readlink(pathPtr, pathLen, outLenPtr) {
  try {
    const linkPath = decodeString(pathPtr, pathLen);
    const target = fs.readlinkSync(linkPath);
    const [ptr, len] = encodeString(target);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    console.error(`[host] fs_readlink error: ${e.message}`);
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

// File watchers storage
const fileWatchers = new Map();
let watcherIdCounter = 1;

function host_fs_watch(pathPtr, pathLen) {
  try {
    const watchPath = decodeString(pathPtr, pathLen);
    const id = watcherIdCounter++;
    const events = [];
    
    const watcher = fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
      events.push({ kind: eventType, path: filename || '' });
    });
    
    fileWatchers.set(id, { watcher, events });
    return id;
  } catch (e) {
    console.error(`[host] fs_watch error: ${e.message}`);
    return -1;
  }
}

function host_fs_watch_poll(handle, outLenPtr) {
  try {
    const w = fileWatchers.get(handle);
    if (!w) {
      writeUsize(outLenPtr, 0);
      return 0;
    }
    const events = w.events.splice(0); // drain events
    const json = JSON.stringify(events);
    const [ptr, len] = encodeString(json);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_fs_watch_close(handle) {
  try {
    const w = fileWatchers.get(handle);
    if (w) {
      w.watcher.close();
      fileWatchers.delete(handle);
    }
    return 0;
  } catch (e) {
    return -1;
  }
}

// ============================================================================
// TCP Networking Imports (via Worker Thread)
// ============================================================================

// Map worker socket IDs to local tracking
const tcpHandleMap = new Map();

function host_tcp_connect(hostPtr, hostLen, port) {
  try {
    const host = decodeString(hostPtr, hostLen);
    
    if (worker) {
      const result = workerCall('tcp_connect', { host, port });
      if (result.ok) {
        tcpHandleMap.set(result.id, { type: 'socket' });
        return result.id;
      } else {
        console.error(`[host] tcp_connect error: ${result.error}`);
        return -1;
      }
    }
    
    // Fallback: use curl for simple HTTP-over-TCP
    console.error('[host] tcp_connect: worker not available');
    return -1;
  } catch (e) {
    console.error(`[host] tcp_connect error: ${e.message}`);
    return -1;
  }
}

function host_tcp_listen(hostPtr, hostLen, port) {
  try {
    const host = decodeString(hostPtr, hostLen);
    
    if (worker) {
      const result = workerCall('tcp_listen', { host, port });
      if (result.ok) {
        tcpHandleMap.set(result.id, { type: 'server' });
        return result.id;
      } else {
        console.error(`[host] tcp_listen error: ${result.error}`);
        return -1;
      }
    }
    
    console.error('[host] tcp_listen: worker not available');
    return -1;
  } catch (e) {
    console.error(`[host] tcp_listen error: ${e.message}`);
    return -1;
  }
}

function host_tcp_accept(serverHandle) {
  try {
    if (worker) {
      const result = workerCall('tcp_accept', { id: serverHandle });
      if (result.ok) {
        tcpHandleMap.set(result.id, { type: 'socket' });
        return result.id;
      } else {
        console.error(`[host] tcp_accept error: ${result.error}`);
        return -1;
      }
    }
    
    console.error('[host] tcp_accept: worker not available');
    return -1;
  } catch (e) {
    console.error(`[host] tcp_accept error: ${e.message}`);
    return -1;
  }
}

function host_tcp_read(handle, bufPtr, bufLen) {
  try {
    if (worker) {
      const result = workerCall('tcp_read', { id: handle, maxLen: bufLen });
      if (result.ok) {
        if (result.data.length === 0) return 0; // EOF
        writeBytes(bufPtr, new Uint8Array(result.data));
        return result.data.length;
      } else {
        console.error(`[host] tcp_read error: ${result.error}`);
        return -1;
      }
    }
    
    console.error('[host] tcp_read: worker not available');
    return -1;
  } catch (e) {
    console.error(`[host] tcp_read error: ${e.message}`);
    return -1;
  }
}

function host_tcp_write(handle, dataPtr, dataLen) {
  try {
    if (worker) {
      const dataBytes = Array.from(new Uint8Array(wasmMemory.buffer, dataPtr, dataLen));
      const result = workerCall('tcp_write', { id: handle, data: dataBytes });
      if (result.ok) {
        return result.written;
      } else {
        console.error(`[host] tcp_write error: ${result.error}`);
        return -1;
      }
    }
    
    console.error('[host] tcp_write: worker not available');
    return -1;
  } catch (e) {
    console.error(`[host] tcp_write error: ${e.message}`);
    return -1;
  }
}

function host_tcp_close(handle) {
  try {
    tcpHandleMap.delete(handle);
    if (worker) {
      workerCall('tcp_close', { id: handle });
    }
    return 0;
  } catch (e) {
    return -1;
  }
}

function host_tcp_local_addr(handle, outLenPtr) {
  try {
    if (worker) {
      const result = workerCall('tcp_local_addr', { id: handle });
      if (result.ok) {
        const [ptr, len] = encodeString(result.addr);
        writeUsize(outLenPtr, len);
        return ptr;
      }
    }
    writeUsize(outLenPtr, 0);
    return 0;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_tcp_remote_addr(handle, outLenPtr) {
  try {
    if (worker) {
      const result = workerCall('tcp_remote_addr', { id: handle });
      if (result.ok) {
        const [ptr, len] = encodeString(result.addr);
        writeUsize(outLenPtr, len);
        return ptr;
      }
    }
    writeUsize(outLenPtr, 0);
    return 0;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_tcp_set_opt(handle, optPtr, optLen, value) {
  // TCP options are set on the worker side, currently no-op
  return 0;
}

// ============================================================================
// HTTP Imports
// ============================================================================

const httpResponses = new Map();
let httpIdCounter = 1;

function host_http_request(methodPtr, methodLen, urlPtr, urlLen, headersPtr, headersLen, bodyPtr, bodyLen) {
  try {
    const method = decodeString(methodPtr, methodLen);
    const urlStr = decodeString(urlPtr, urlLen);
    const headers = headersPtr && headersLen > 0 ? JSON.parse(decodeString(headersPtr, headersLen)) : {};
    const body = bodyPtr && bodyLen > 0 ? Buffer.from(new Uint8Array(wasmMemory.buffer, bodyPtr, bodyLen)) : null;
    
    // Use curl for truly synchronous HTTP (execSync blocks properly)
    // Build curl command
    let curlArgs = ['-s', '-S', '-i', '-X', method];
    
    // Add headers
    for (const [key, value] of Object.entries(headers)) {
      curlArgs.push('-H', `${key}: ${value}`);
    }
    
    // Add body
    if (body && body.length > 0) {
      curlArgs.push('-d', body.toString());
    }
    
    curlArgs.push(urlStr);
    
    try {
      const result = spawnSync('curl', curlArgs, {
        encoding: 'buffer',
        maxBuffer: 50 * 1024 * 1024,
        timeout: 60000,
      });
      
      if (result.error) {
        console.error(`[host] http_request curl error: ${result.error.message}`);
        return -1;
      }
      
      // Parse response (headers + body separated by \r\n\r\n)
      const output = result.stdout;
      const headerEndIdx = output.indexOf('\r\n\r\n');
      let statusCode = 200;
      let responseHeaders = {};
      let responseBody = output;
      
      if (headerEndIdx > 0) {
        const headerPart = output.subarray(0, headerEndIdx).toString();
        responseBody = output.subarray(headerEndIdx + 4);
        
        // Parse status line: HTTP/1.1 200 OK
        const lines = headerPart.split('\r\n');
        const statusLine = lines[0];
        const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)/);
        if (statusMatch) {
          statusCode = parseInt(statusMatch[1], 10);
        }
        
        // Parse headers
        for (let i = 1; i < lines.length; i++) {
          const colonIdx = lines[i].indexOf(':');
          if (colonIdx > 0) {
            const key = lines[i].substring(0, colonIdx).toLowerCase();
            const value = lines[i].substring(colonIdx + 1).trim();
            responseHeaders[key] = value;
          }
        }
      }
      
      const id = httpIdCounter++;
      httpResponses.set(id, {
        status: statusCode,
        headers: responseHeaders,
        body: responseBody,
      });
      
      return id;
    } catch (curlError) {
      console.error(`[host] http_request error: ${curlError.message}`);
      return -1;
    }
  } catch (e) {
    console.error(`[host] http_request error: ${e.message}`);
    return -1;
  }
}

function host_http_status(handle) {
  const r = httpResponses.get(handle);
  return r ? r.status : -1;
}

function host_http_headers(handle, outLenPtr) {
  try {
    const r = httpResponses.get(handle);
    if (!r) {
      writeUsize(outLenPtr, 0);
      return 0;
    }
    const json = JSON.stringify(r.headers);
    const [ptr, len] = encodeString(json);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_http_body(handle, outLenPtr) {
  try {
    const r = httpResponses.get(handle);
    if (!r || !r.body) {
      writeUsize(outLenPtr, 0);
      return 0;
    }
    const ptr = hostAlloc(r.body.length);
    writeBytes(ptr, r.body);
    writeUsize(outLenPtr, r.body.length);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_http_free(handle) {
  httpResponses.delete(handle);
  return 0;
}

// ============================================================================
// Async / Event Loop Imports
// ============================================================================

// ============================================================================
// Async / Event Loop Imports (via Worker Thread)
// ============================================================================

function host_timer_set(ms) {
  if (worker) {
    const result = workerCall('timer_set', { ms });
    if (result.ok) return result.id;
  }
  // Fallback: just return a dummy ID (timer won't fire properly without worker)
  return 0;
}

function host_timer_cancel(handle) {
  if (worker) {
    workerCall('timer_cancel', { id: handle });
  }
  return 0;
}

function host_poll(outLenPtr) {
  if (worker) {
    const result = workerCall('poll', {});
    if (result.ok && result.event) {
      const json = JSON.stringify(result.event);
      const [ptr, len] = encodeString(json);
      writeUsize(outLenPtr, len);
      return ptr;
    }
  }
  writeUsize(outLenPtr, 0);
  return 0;
}

function host_wait(timeoutMs) {
  if (worker) {
    const result = workerCall('wait', { timeoutMs });
    if (result.ok) return result.count;
  }
  // Fallback: simple sleep
  if (timeoutMs > 0) {
    const sab = new SharedArrayBuffer(4);
    Atomics.wait(new Int32Array(sab), 0, 0, timeoutMs);
  }
  return 0;
}

function host_poll_read(handle) {
  // Would register interest in socket - handled by worker
  return 0;
}

function host_poll_write(handle) {
  // Would register interest in socket - handled by worker
  return 0;
}

function host_poll_remove(handle) {
  return 0;
}

function host_time_now() {
  return BigInt(Date.now());
}

function host_sleep(ms) {
  if (worker) {
    workerCall('sleep', { ms });
  } else {
    // Fallback: busy wait (not great, but works)
    const sab = new SharedArrayBuffer(4);
    Atomics.wait(new Int32Array(sab), 0, 0, ms);
  }
}

// ============================================================================
// Streams Imports
// ============================================================================

const streams = new Map();
let streamIdCounter = 1;

function host_stream_open(pathPtr, pathLen, modePtr, modeLen) {
  try {
    const filePath = decodeString(pathPtr, pathLen);
    const mode = decodeString(modePtr, modeLen);
    
    // Convert mode to flags
    let flags;
    switch (mode) {
      case 'r': flags = 'r'; break;
      case 'w': flags = 'w'; break;
      case 'a': flags = 'a'; break;
      case 'r+': flags = 'r+'; break;
      case 'w+': flags = 'w+'; break;
      case 'a+': flags = 'a+'; break;
      default: flags = 'r';
    }
    
    const fd = fs.openSync(filePath, flags);
    const id = streamIdCounter++;
    streams.set(id, { fd, position: 0 });
    return id;
  } catch (e) {
    console.error(`[host] stream_open error: ${e.message}`);
    return -1;
  }
}

function host_stream_read(handle, bufPtr, bufLen) {
  try {
    const s = streams.get(handle);
    if (!s) return -1;
    
    const buffer = Buffer.alloc(bufLen);
    const bytesRead = fs.readSync(s.fd, buffer, 0, bufLen, s.position);
    
    if (bytesRead > 0) {
      writeBytes(bufPtr, buffer.subarray(0, bytesRead));
      s.position += bytesRead;
    }
    
    return bytesRead;
  } catch (e) {
    console.error(`[host] stream_read error: ${e.message}`);
    return -1;
  }
}

function host_stream_write(handle, dataPtr, dataLen) {
  try {
    const s = streams.get(handle);
    if (!s) return -1;
    
    const data = Buffer.from(new Uint8Array(wasmMemory.buffer, dataPtr, dataLen));
    const bytesWritten = fs.writeSync(s.fd, data, 0, dataLen, s.position);
    s.position += bytesWritten;
    
    return bytesWritten;
  } catch (e) {
    console.error(`[host] stream_write error: ${e.message}`);
    return -1;
  }
}

function host_stream_seek(handle, offsetLow, offsetHigh, whence) {
  // Note: offset is i64, passed as two i32s in WASM
  try {
    const s = streams.get(handle);
    if (!s) return -1n;
    
    const offset = BigInt(offsetLow) | (BigInt(offsetHigh) << 32n);
    const stat = fs.fstatSync(s.fd);
    
    let newPos;
    switch (whence) {
      case 0: newPos = offset; break; // SEEK_SET
      case 1: newPos = BigInt(s.position) + offset; break; // SEEK_CUR
      case 2: newPos = BigInt(stat.size) + offset; break; // SEEK_END
      default: return -1n;
    }
    
    s.position = Number(newPos);
    return newPos;
  } catch (e) {
    console.error(`[host] stream_seek error: ${e.message}`);
    return -1n;
  }
}

function host_stream_tell(handle) {
  const s = streams.get(handle);
  return s ? BigInt(s.position) : -1n;
}

function host_stream_flush(handle) {
  try {
    const s = streams.get(handle);
    if (!s) return -1;
    fs.fsyncSync(s.fd);
    return 0;
  } catch (e) {
    return -1;
  }
}

function host_stream_close(handle) {
  try {
    const s = streams.get(handle);
    if (s) {
      fs.closeSync(s.fd);
      streams.delete(handle);
    }
    return 0;
  } catch (e) {
    return -1;
  }
}

function host_pipe_create(outWritePtr) {
  // Node.js doesn't have true pipes easily accessible synchronously
  // Create a temp file pair as workaround
  try {
    const tmpPath = path.join(process.env.TEMP || '/tmp', `polyglot-pipe-${Date.now()}`);
    fs.writeFileSync(tmpPath, '');
    
    const readFd = fs.openSync(tmpPath, 'r');
    const writeFd = fs.openSync(tmpPath, 'a');
    
    const readId = streamIdCounter++;
    const writeId = streamIdCounter++;
    
    streams.set(readId, { fd: readFd, position: 0 });
    streams.set(writeId, { fd: writeFd, position: 0 });
    
    writeUsize(outWritePtr, writeId);
    return readId;
  } catch (e) {
    console.error(`[host] pipe_create error: ${e.message}`);
    return -1;
  }
}

// ============================================================================
// Environment Imports
// ============================================================================

function host_env_get(namePtr, nameLen, outLenPtr) {
  try {
    const name = decodeString(namePtr, nameLen);
    const value = process.env[name];
    if (value === undefined) {
      writeUsize(outLenPtr, 0);
      return 0;
    }
    const [ptr, len] = encodeString(value);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_env_set(namePtr, nameLen, valPtr, valLen) {
  try {
    const name = decodeString(namePtr, nameLen);
    const value = decodeString(valPtr, valLen);
    process.env[name] = value;
    return 0;
  } catch (e) {
    return -1;
  }
}

function host_env_cwd(outLenPtr) {
  try {
    const cwd = process.cwd();
    const [ptr, len] = encodeString(cwd);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

function host_env_chdir(pathPtr, pathLen) {
  try {
    const newPath = decodeString(pathPtr, pathLen);
    process.chdir(newPath);
    return 0;
  } catch (e) {
    return -1;
  }
}

function host_env_args(outLenPtr) {
  try {
    // Skip node and script path, return remaining args
    const args = wasmArgs || [];
    const json = JSON.stringify(args);
    const [ptr, len] = encodeString(json);
    writeUsize(outLenPtr, len);
    return ptr;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

// ============================================================================
// Console Imports
// ============================================================================

function host_console_log(msgPtr, msgLen) {
  const msg = decodeString(msgPtr, msgLen);
  console.log(msg);
}

function host_console_error(msgPtr, msgLen) {
  const msg = decodeString(msgPtr, msgLen);
  console.error(msg);
}

function host_console_read_line(outLenPtr) {
  // Synchronous readline - blocks the event loop
  // For production, use async with worker threads
  try {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    
    let line = '';
    rl.on('line', (input) => {
      line = input;
      rl.close();
    });
    
    // This is hacky - for proper impl use worker threads or Atomics
    // For now, just return empty
    writeUsize(outLenPtr, 0);
    return 0;
  } catch (e) {
    writeUsize(outLenPtr, 0);
    return 0;
  }
}

// ============================================================================
// Process Imports
// ============================================================================

function host_process_exec(cmdPtr, cmdLen, outStdoutLenPtr, outStderrLenPtr, outStdoutPtrPtr, outStderrPtrPtr) {
  try {
    const cmd = decodeString(cmdPtr, cmdLen);
    
    const result = spawnSync(cmd, {
      shell: true,
      encoding: 'buffer',
      maxBuffer: 50 * 1024 * 1024, // 50MB
    });
    
    // Write stdout
    if (result.stdout && result.stdout.length > 0) {
      const stdoutPtr = hostAlloc(result.stdout.length);
      writeBytes(stdoutPtr, result.stdout);
      writeUsize(outStdoutLenPtr, result.stdout.length);
      writePtr(outStdoutPtrPtr, stdoutPtr);
    } else {
      writeUsize(outStdoutLenPtr, 0);
      writePtr(outStdoutPtrPtr, 0);
    }
    
    // Write stderr
    if (result.stderr && result.stderr.length > 0) {
      const stderrPtr = hostAlloc(result.stderr.length);
      writeBytes(stderrPtr, result.stderr);
      writeUsize(outStderrLenPtr, result.stderr.length);
      writePtr(outStderrPtrPtr, stderrPtr);
    } else {
      writeUsize(outStderrLenPtr, 0);
      writePtr(outStderrPtrPtr, 0);
    }
    
    return result.status ?? -1;
  } catch (e) {
    console.error(`[host] process_exec error: ${e.message}`);
    writeUsize(outStdoutLenPtr, 0);
    writeUsize(outStderrLenPtr, 0);
    writePtr(outStdoutPtrPtr, 0);
    writePtr(outStderrPtrPtr, 0);
    return -1;
  }
}

function host_process_exit(code) {
  process.exit(code);
}

// ============================================================================
// Host Memory Exports (for WASM to allocate)
// ============================================================================

function host_alloc(size) {
  return hostAlloc(size);
}

function host_free(ptr, size) {
  return hostFree(ptr, size);
}

function host_get_len(ptr) {
  // Not implemented - would need length tracking
  return 0;
}

// ============================================================================
// Import Object
// ============================================================================

const hostImports = {
  host: {
    // Memory
    host_alloc,
    host_free,
    host_get_len,
    
    // Filesystem (basic)
    host_fs_read,
    host_fs_write,
    host_fs_append,
    host_fs_exists,
    host_fs_is_dir,
    host_fs_mkdir,
    host_fs_remove,
    host_fs_rmdir,
    host_fs_readdir,
    
    // Filesystem (extended)
    host_fs_stat,
    host_fs_rename,
    host_fs_copy,
    host_fs_symlink,
    host_fs_readlink,
    host_fs_watch,
    host_fs_watch_poll,
    host_fs_watch_close,
    
    // Environment
    host_env_get,
    host_env_set,
    host_env_cwd,
    host_env_chdir,
    host_env_args,
    
    // Console
    host_console_log,
    host_console_error,
    host_console_read_line,
    
    // Process
    host_process_exec,
    host_process_exit,
    
    // TCP Networking
    host_tcp_connect,
    host_tcp_listen,
    host_tcp_accept,
    host_tcp_read,
    host_tcp_write,
    host_tcp_close,
    host_tcp_local_addr,
    host_tcp_remote_addr,
    host_tcp_set_opt,
    
    // HTTP
    host_http_request,
    host_http_status,
    host_http_headers,
    host_http_body,
    host_http_free,
    
    // Async / Event Loop
    host_timer_set,
    host_timer_cancel,
    host_poll,
    host_wait,
    host_poll_read,
    host_poll_write,
    host_poll_remove,
    host_time_now,
    host_sleep,
    
    // Streams
    host_stream_open,
    host_stream_read,
    host_stream_write,
    host_stream_seek,
    host_stream_tell,
    host_stream_flush,
    host_stream_close,
    host_pipe_create,
  },
};

// ============================================================================
// Main Entry Point
// ============================================================================

let wasmArgs = [];

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Polyglot Host — Node.js runtime for Polyglot WASM');
    console.log('');
    console.log('Usage: node polyglot-host.mjs <wasm-file> [args...]');
    console.log('');
    console.log('Example:');
    console.log('  node polyglot-host.mjs app.wasm --config config.json');
    process.exit(0);
  }
  
  const wasmPath = args[0];
  wasmArgs = args.slice(1);
  
  if (!fs.existsSync(wasmPath)) {
    console.error(`Error: WASM file not found: ${wasmPath}`);
    process.exit(1);
  }
  
  // Initialize async worker thread
  initWorker();
  
  console.log(`[host] Loading: ${wasmPath}`);
  console.log(`[host] Args: ${JSON.stringify(wasmArgs)}`);
  
  try {
    const wasmBuffer = fs.readFileSync(wasmPath);
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    
    // Check what imports the module needs
    const imports = WebAssembly.Module.imports(wasmModule);
    console.log(`[host] Module imports: ${imports.length}`);
    
    // Create memory if module doesn't export it
    const memory = new WebAssembly.Memory({ initial: 256, maximum: 65536 }); // 16MB - 4GB
    
    // WASI stubs for compatibility (minimal implementation)
    const wasiStubs = {
      proc_exit: (code) => process.exit(code),
      fd_write: (fd, iovs_ptr, iovs_len, nwritten_ptr) => {
        // Stub: write to stdout/stderr
        return 0;
      },
      fd_read: () => 0,
      fd_close: () => 0,
      fd_seek: () => 0,
      fd_fdstat_get: () => 0,
      fd_prestat_get: () => 8, // EBADF
      fd_prestat_dir_name: () => 8,
      environ_sizes_get: (count_ptr, buf_size_ptr) => 0,
      environ_get: () => 0,
      args_sizes_get: (argc_ptr, argv_buf_size_ptr) => 0,
      args_get: () => 0,
      clock_time_get: (id, precision, time_ptr) => 0,
      random_get: (buf, len) => {
        // Fill with random bytes
        return 0;
      },
    };

    // Add memory and WASI to imports
    const finalImports = {
      ...hostImports,
      env: {
        memory,
      },
      wasi_snapshot_preview1: wasiStubs,
    };
    
    // Instantiate
    const instance = await WebAssembly.instantiate(wasmModule, finalImports);
    wasmInstance = instance;
    
    // Use exported memory if available, otherwise use our memory
    const exportedMemory = instance.exports.memory;
    initHeap(exportedMemory || memory);
    
    console.log(`[host] Exports: ${Object.keys(instance.exports).join(', ')}`);
    
    // Call main or _start
    if (typeof instance.exports.main === 'function') {
      console.log('[host] Calling main()...');
      console.log('─'.repeat(50));
      const result = instance.exports.main();
      console.log('─'.repeat(50));
      console.log(`[host] main() returned: ${result}`);
    } else if (typeof instance.exports._start === 'function') {
      console.log('[host] Calling _start()...');
      console.log('─'.repeat(50));
      instance.exports._start();
      console.log('─'.repeat(50));
      console.log('[host] _start() completed');
    } else {
      console.error('[host] No main() or _start() export found');
      process.exit(1);
    }
    
  } catch (e) {
    console.error(`[host] Error: ${e.message}`);
    console.error(e.stack);
    process.exit(1);
  }
}

main();
