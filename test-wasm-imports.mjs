import fs from 'fs';

const wasmPath = process.argv[2] || 'examples/pure_math.wasm';
const buffer = fs.readFileSync(wasmPath);
const module = new WebAssembly.Module(buffer);

console.log('Imports:');
for (const imp of WebAssembly.Module.imports(module)) {
    console.log(`  ${imp.module}.${imp.name}: ${imp.kind}`);
}

console.log('\nExports:');
for (const exp of WebAssembly.Module.exports(module)) {
    console.log(`  ${exp.name}: ${exp.kind}`);
}
