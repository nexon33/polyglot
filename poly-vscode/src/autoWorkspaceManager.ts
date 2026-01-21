import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Manages temporary Cargo workspaces for .poly files opened outside of Rust projects.
 * This allows rust-analyzer to work properly with embedded Rust code.
 */
export class AutoWorkspaceManager {
    private tempWorkspaces: Map<string, string> = new Map();
    private tempDir: string;

    constructor() {
        this.tempDir = path.join(os.tmpdir(), 'polyglot-workspaces');
        if (!fs.existsSync(this.tempDir)) {
            fs.mkdirSync(this.tempDir, { recursive: true });
        }
    }

    /**
     * Check if a .poly file needs a temporary workspace (no Cargo.toml in parent directories)
     */
    needsWorkspace(polyUri: vscode.Uri): boolean {
        let dir = path.dirname(polyUri.fsPath);

        // Walk up the directory tree looking for Cargo.toml
        while (dir && dir !== path.dirname(dir)) {
            if (fs.existsSync(path.join(dir, 'Cargo.toml'))) {
                return false; // Found a Cargo.toml, no temp workspace needed
            }
            dir = path.dirname(dir);
        }

        return true; // No Cargo.toml found, need temp workspace
    }

    /**
     * Create a temporary Cargo workspace for a .poly file
     */
    createWorkspace(polyUri: vscode.Uri, rustCode: string): string {
        const polyPath = polyUri.fsPath;
        const polyName = path.basename(polyPath, '.poly');
        const workspaceId = this.hashPath(polyPath);
        const workspacePath = path.join(this.tempDir, workspaceId);

        // Check if we already have this workspace
        if (this.tempWorkspaces.has(polyPath)) {
            return this.tempWorkspaces.get(polyPath)!;
        }

        // Create workspace directory structure
        const srcDir = path.join(workspacePath, 'src');
        if (!fs.existsSync(srcDir)) {
            fs.mkdirSync(srcDir, { recursive: true });
        }

        // Extract dependencies from rust code
        const deps = this.extractDependencies(rustCode);

        // Create Cargo.toml
        const cargoToml = this.generateCargoToml(polyName, deps);
        fs.writeFileSync(path.join(workspacePath, 'Cargo.toml'), cargoToml);

        // Write the Rust code to lib.rs
        fs.writeFileSync(path.join(srcDir, 'lib.rs'), rustCode);

        // Create rust-project.json for rust-analyzer
        const rustProject = {
            sysroot_src: null,
            crates: [
                {
                    root_module: path.join(srcDir, 'lib.rs'),
                    edition: '2021',
                    deps: []
                }
            ]
        };
        fs.writeFileSync(
            path.join(workspacePath, 'rust-project.json'),
            JSON.stringify(rustProject, null, 2)
        );

        this.tempWorkspaces.set(polyPath, workspacePath);
        return workspacePath;
    }

    /**
     * Update the Rust code in an existing workspace
     */
    updateWorkspace(polyUri: vscode.Uri, rustCode: string): void {
        const polyPath = polyUri.fsPath;
        const workspacePath = this.tempWorkspaces.get(polyPath);

        if (workspacePath) {
            const libPath = path.join(workspacePath, 'src', 'lib.rs');
            fs.writeFileSync(libPath, rustCode);
        }
    }

    /**
     * Extract crate dependencies from use statements
     */
    private extractDependencies(rustCode: string): Map<string, string> {
        const deps = new Map<string, string>();

        // Match use statements: use serde::..., use tokio::..., etc.
        const useRegex = /\buse\s+([a-z_][a-z0-9_]*)::/g;
        let match;

        // Common crates and their versions
        const knownCrates: Record<string, string> = {
            'serde': '1.0',
            'serde_json': '1.0',
            'tokio': '1',
            'anyhow': '1',
            'thiserror': '1',
            'regex': '1',
            'log': '0.4',
            'tracing': '0.1',
            'clap': '4',
            'rand': '0.8',
            'chrono': '0.4',
            'reqwest': '0.11',
            'hyper': '1',
            'axum': '0.7',
            'sqlx': '0.7',
            'diesel': '2',
        };

        while ((match = useRegex.exec(rustCode)) !== null) {
            const crate = match[1];
            if (crate !== 'std' && crate !== 'core' && crate !== 'alloc' && crate !== 'crate' && crate !== 'super' && crate !== 'self') {
                if (knownCrates[crate]) {
                    deps.set(crate, knownCrates[crate]);
                } else {
                    deps.set(crate, '*'); // Unknown version
                }
            }
        }

        return deps;
    }

    /**
     * Generate Cargo.toml content
     */
    private generateCargoToml(name: string, deps: Map<string, string>): string {
        let toml = `[package]
name = "${name.replace(/[^a-zA-Z0-9_-]/g, '_')}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
`;

        for (const [crate, version] of deps) {
            if (version === '*') {
                toml += `# ${crate} = "*" # Unknown version\n`;
            } else {
                toml += `${crate} = "${version}"\n`;
            }
        }

        return toml;
    }

    /**
     * Create a simple hash of the file path for workspace naming
     */
    private hashPath(filePath: string): string {
        let hash = 0;
        for (let i = 0; i < filePath.length; i++) {
            const char = filePath.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return 'poly_' + Math.abs(hash).toString(16);
    }

    /**
     * Get the workspace path for a .poly file
     */
    getWorkspacePath(polyUri: vscode.Uri): string | undefined {
        return this.tempWorkspaces.get(polyUri.fsPath);
    }

    /**
     * Clean up temporary workspaces
     */
    dispose(): void {
        for (const workspacePath of this.tempWorkspaces.values()) {
            try {
                fs.rmSync(workspacePath, { recursive: true, force: true });
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        this.tempWorkspaces.clear();
    }
}
