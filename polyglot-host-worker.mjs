/**
 * Polyglot Host Worker — Async operations handler
 * 
 * This worker receives async operation requests from the main thread,
 * performs them, and signals completion via SharedArrayBuffer.
 */

import { parentPort, workerData } from 'worker_threads';
import net from 'net';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { URL } from 'url';

// Shared memory for signaling
const { signalBuffer, dataBuffer } = workerData;
const signal = new Int32Array(signalBuffer);
const data = new Uint8Array(dataBuffer);

// Constants for signal states
const IDLE = 0;
const REQUEST_PENDING = 1;
const RESPONSE_READY = 2;

// TCP socket storage
const sockets = new Map();
const servers = new Map();
let socketIdCounter = 1;

// Write result to shared data buffer
function writeResult(result) {
  const json = JSON.stringify(result);
  const encoded = new TextEncoder().encode(json);
  // First 4 bytes = length
  const view = new DataView(dataBuffer);
  view.setUint32(0, encoded.length, true);
  data.set(encoded, 4);
}

// Handle TCP connect
async function tcpConnect(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const id = socketIdCounter++;
    
    socket.connect(port, host, () => {
      sockets.set(id, { socket, readBuffer: [] });
      
      socket.on('data', (chunk) => {
        const s = sockets.get(id);
        if (s) s.readBuffer.push(chunk);
      });
      
      socket.on('close', () => {
        const s = sockets.get(id);
        if (s) s.closed = true;
      });
      
      socket.on('error', () => {
        const s = sockets.get(id);
        if (s) s.error = true;
      });
      
      resolve({ ok: true, id });
    });
    
    socket.on('error', (err) => {
      resolve({ ok: false, error: err.message });
    });
    
    // Timeout
    setTimeout(() => {
      if (!sockets.has(id)) {
        socket.destroy();
        resolve({ ok: false, error: 'Connection timeout' });
      }
    }, 30000);
  });
}

// Handle TCP read
async function tcpRead(id, maxLen) {
  return new Promise((resolve) => {
    const s = sockets.get(id);
    if (!s) {
      resolve({ ok: false, error: 'Invalid socket' });
      return;
    }
    
    // Check if data already buffered
    if (s.readBuffer.length > 0) {
      const combined = Buffer.concat(s.readBuffer);
      const toReturn = combined.subarray(0, maxLen);
      s.readBuffer = combined.length > maxLen ? [combined.subarray(maxLen)] : [];
      resolve({ ok: true, data: Array.from(toReturn) });
      return;
    }
    
    // Check if closed
    if (s.closed) {
      resolve({ ok: true, data: [] }); // EOF
      return;
    }
    
    // Wait for data
    const onData = (chunk) => {
      s.socket.off('data', onData);
      s.socket.off('close', onClose);
      s.socket.off('error', onError);
      clearTimeout(timeout);
      
      const toReturn = chunk.subarray(0, maxLen);
      if (chunk.length > maxLen) {
        s.readBuffer.push(chunk.subarray(maxLen));
      }
      resolve({ ok: true, data: Array.from(toReturn) });
    };
    
    const onClose = () => {
      s.socket.off('data', onData);
      s.socket.off('error', onError);
      clearTimeout(timeout);
      resolve({ ok: true, data: [] }); // EOF
    };
    
    const onError = (err) => {
      s.socket.off('data', onData);
      s.socket.off('close', onClose);
      clearTimeout(timeout);
      resolve({ ok: false, error: err.message });
    };
    
    const timeout = setTimeout(() => {
      s.socket.off('data', onData);
      s.socket.off('close', onClose);
      s.socket.off('error', onError);
      resolve({ ok: false, error: 'Read timeout' });
    }, 30000);
    
    s.socket.once('data', onData);
    s.socket.once('close', onClose);
    s.socket.once('error', onError);
  });
}

// Handle TCP write
function tcpWrite(id, bytes) {
  const s = sockets.get(id);
  if (!s) return { ok: false, error: 'Invalid socket' };
  
  try {
    const buffer = Buffer.from(bytes);
    s.socket.write(buffer);
    return { ok: true, written: buffer.length };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// Handle TCP close
function tcpClose(id) {
  const s = sockets.get(id);
  if (s) {
    s.socket.destroy();
    sockets.delete(id);
  }
  return { ok: true };
}

// Handle TCP listen
async function tcpListen(host, port) {
  return new Promise((resolve) => {
    const id = socketIdCounter++;
    const server = net.createServer();
    const pendingConnections = [];
    
    server.on('connection', (socket) => {
      const connId = socketIdCounter++;
      sockets.set(connId, { socket, readBuffer: [] });
      
      socket.on('data', (chunk) => {
        const s = sockets.get(connId);
        if (s) s.readBuffer.push(chunk);
      });
      
      socket.on('close', () => {
        const s = sockets.get(connId);
        if (s) s.closed = true;
      });
      
      pendingConnections.push(connId);
    });
    
    server.listen(port, host, () => {
      servers.set(id, { server, pendingConnections });
      resolve({ ok: true, id });
    });
    
    server.on('error', (err) => {
      resolve({ ok: false, error: err.message });
    });
  });
}

// Handle TCP accept
async function tcpAccept(serverId) {
  return new Promise((resolve) => {
    const s = servers.get(serverId);
    if (!s) {
      resolve({ ok: false, error: 'Invalid server' });
      return;
    }
    
    // Check if connection already pending
    if (s.pendingConnections.length > 0) {
      resolve({ ok: true, id: s.pendingConnections.shift() });
      return;
    }
    
    // Wait for connection
    const onConnection = (socket) => {
      clearTimeout(timeout);
      const connId = socketIdCounter++;
      sockets.set(connId, { socket, readBuffer: [] });
      
      socket.on('data', (chunk) => {
        const ss = sockets.get(connId);
        if (ss) ss.readBuffer.push(chunk);
      });
      
      resolve({ ok: true, id: connId });
    };
    
    const timeout = setTimeout(() => {
      s.server.off('connection', onConnection);
      resolve({ ok: false, error: 'Accept timeout' });
    }, 60000);
    
    s.server.once('connection', onConnection);
  });
}

// Handle HTTP request
async function httpRequest(method, url, headers, body) {
  return new Promise((resolve) => {
    try {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === 'https:';
      const lib = isHttps ? https : http;
      
      const options = {
        method,
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        headers: headers || {},
      };
      
      const req = lib.request(options, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const responseBody = Buffer.concat(chunks);
          resolve({
            ok: true,
            status: res.statusCode,
            headers: res.headers,
            body: Array.from(responseBody),
          });
        });
      });
      
      req.on('error', (err) => {
        resolve({ ok: false, error: err.message });
      });
      
      req.setTimeout(60000, () => {
        req.destroy();
        resolve({ ok: false, error: 'Request timeout' });
      });
      
      if (body && body.length > 0) {
        req.write(Buffer.from(body));
      }
      req.end();
    } catch (err) {
      resolve({ ok: false, error: err.message });
    }
  });
}

// Handle sleep
async function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(() => resolve({ ok: true }), ms);
  });
}

// Handle timer (returns immediately, fires event later)
const timers = new Map();
let timerIdCounter = 1;
const timerEvents = [];

function timerSet(ms) {
  const id = timerIdCounter++;
  const timer = setTimeout(() => {
    timers.delete(id);
    timerEvents.push({ type: 'timer', handle: id });
  }, ms);
  timers.set(id, timer);
  return { ok: true, id };
}

function timerCancel(id) {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
  return { ok: true };
}

// Poll for events
function pollEvents() {
  if (timerEvents.length > 0) {
    return { ok: true, event: timerEvents.shift() };
  }
  return { ok: true, event: null };
}

// Wait for events
async function waitEvents(timeoutMs) {
  if (timerEvents.length > 0) {
    return { ok: true, count: timerEvents.length };
  }
  
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve({ ok: true, count: timerEvents.length });
    }, timeoutMs || 1000);
    
    // Check periodically
    const interval = setInterval(() => {
      if (timerEvents.length > 0) {
        clearTimeout(timeout);
        clearInterval(interval);
        resolve({ ok: true, count: timerEvents.length });
      }
    }, 10);
  });
}

// Main message handler
async function handleRequest(request) {
  const { op, args } = request;
  
  switch (op) {
    case 'tcp_connect':
      return await tcpConnect(args.host, args.port);
    case 'tcp_read':
      return await tcpRead(args.id, args.maxLen);
    case 'tcp_write':
      return tcpWrite(args.id, args.data);
    case 'tcp_close':
      return tcpClose(args.id);
    case 'tcp_listen':
      return await tcpListen(args.host, args.port);
    case 'tcp_accept':
      return await tcpAccept(args.id);
    case 'tcp_local_addr': {
      const s = sockets.get(args.id) || servers.get(args.id);
      if (!s) return { ok: false, error: 'Invalid handle' };
      const addr = s.socket ? s.socket.address() : s.server.address();
      return { ok: true, addr: `${addr.address}:${addr.port}` };
    }
    case 'tcp_remote_addr': {
      const s = sockets.get(args.id);
      if (!s) return { ok: false, error: 'Invalid socket' };
      return { ok: true, addr: `${s.socket.remoteAddress}:${s.socket.remotePort}` };
    }
    case 'http_request':
      return await httpRequest(args.method, args.url, args.headers, args.body);
    case 'sleep':
      return await sleep(args.ms);
    case 'timer_set':
      return timerSet(args.ms);
    case 'timer_cancel':
      return timerCancel(args.id);
    case 'poll':
      return pollEvents();
    case 'wait':
      return await waitEvents(args.timeoutMs);
    default:
      return { ok: false, error: `Unknown operation: ${op}` };
  }
}

// Main loop: wait for requests, process them, signal completion
async function mainLoop() {
  while (true) {
    // Wait for request (signal[0] == REQUEST_PENDING)
    const waitResult = Atomics.wait(signal, 0, IDLE);
    if (waitResult === 'not-equal') {
      // Request is already pending
    }
    
    if (Atomics.load(signal, 0) !== REQUEST_PENDING) {
      // Spurious wake, continue waiting
      continue;
    }
    
    // Read request from data buffer
    const view = new DataView(dataBuffer);
    const reqLen = view.getUint32(0, true);
    const reqBytes = data.subarray(4, 4 + reqLen);
    const reqJson = new TextDecoder().decode(reqBytes);
    const request = JSON.parse(reqJson);
    
    // Process request
    const result = await handleRequest(request);
    
    // Write result
    writeResult(result);
    
    // Signal completion
    Atomics.store(signal, 0, RESPONSE_READY);
    Atomics.notify(signal, 0);
  }
}

mainLoop().catch(console.error);
