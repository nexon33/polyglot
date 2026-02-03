#!/usr/bin/env node
/**
 * Polyglot Host — Node.js runtime for Polyglot WASM modules
 * 
 * Provides filesystem, environment, console, and process imports
 * that bridge WASM to Node.js native capabilities.
 * 
 * Usage: node polyglot-host.mjs <path-to-wasm> [args...]
 */

import fs from 'fs';
import path from 'path';
import { execSync, spawnSync } from 'child_process';
import readline from 'readline';

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
    host_alloc,
    host_free,
    host_get_len,
    host_fs_read,
    host_fs_write,
    host_fs_append,
    host_fs_exists,
    host_fs_is_dir,
    host_fs_mkdir,
    host_fs_remove,
    host_fs_rmdir,
    host_fs_readdir,
    host_env_get,
    host_env_set,
    host_env_cwd,
    host_env_chdir,
    host_env_args,
    host_console_log,
    host_console_error,
    host_console_read_line,
    host_process_exec,
    host_process_exit,
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
    
    // Add memory to imports if needed
    const finalImports = {
      ...hostImports,
      env: {
        memory,
      },
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
