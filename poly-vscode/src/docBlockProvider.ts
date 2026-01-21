import * as vscode from 'vscode';

interface DocBlock {
    targetPath: string;
    targetSymbol?: string;
    content: string;
    startLine: number;
    endLine: number;
}

interface WikiLink {
    symbol: string;
    range: vscode.Range;
}

/**
 * Provides inline documentation support for #[doc:path:symbol] blocks.
 * - Renders docs as hover/panel
 * - Supports [[symbol]] wiki-style links
 */
export class DocBlockProvider implements vscode.HoverProvider, vscode.DocumentLinkProvider {
    private _docBlocks: Map<string, DocBlock[]> = new Map();

    constructor() { }

    /**
     * Parse doc blocks from a .poly file
     */
    parseDocBlocks(uri: vscode.Uri, text: string): void {
        const blocks: DocBlock[] = [];

        // Match #[doc:path] or #[doc:path:symbol]
        const docRegex = /^#\[doc(?::([^\]:]+))?(?::([^\]]+))?\]\s*\n([\s\S]*?)(?=\n#\[|$)/gm;
        let match;

        while ((match = docRegex.exec(text)) !== null) {
            const targetPath = match[1] || '*';
            const targetSymbol = match[2];
            const content = match[3].trim();

            const startLine = text.substring(0, match.index).split('\n').length - 1;
            const endLine = startLine + match[0].split('\n').length;

            blocks.push({
                targetPath,
                targetSymbol,
                content,
                startLine,
                endLine
            });
        }

        this._docBlocks.set(uri.toString(), blocks);
    }

    /**
     * Find doc block for a given symbol
     */
    findDocForSymbol(uri: vscode.Uri, symbol: string): DocBlock | undefined {
        const blocks = this._docBlocks.get(uri.toString()) || [];
        return blocks.find(b => b.targetSymbol === symbol);
    }

    /**
     * VSCode HoverProvider - show docs on function hover
     */
    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | undefined> {
        // Get word at position
        const wordRange = document.getWordRangeAtPosition(position);
        if (!wordRange) return undefined;

        const word = document.getText(wordRange);

        // Check if there's a doc block for this symbol
        const docBlock = this.findDocForSymbol(document.uri, word);
        if (!docBlock) return undefined;

        const markdown = new vscode.MarkdownString();
        markdown.appendMarkdown(`## 📖 ${word}\n\n`);
        markdown.appendMarkdown(docBlock.content);
        markdown.isTrusted = true;

        return new vscode.Hover(markdown, wordRange);
    }

    /**
     * VSCode DocumentLinkProvider - make [[symbol]] links clickable
     */
    provideDocumentLinks(
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): vscode.DocumentLink[] {
        const links: vscode.DocumentLink[] = [];
        const text = document.getText();

        // Find all [[symbol]] patterns
        const wikiLinkRegex = /\[\[([^\]]+)\]\]/g;
        let match;

        while ((match = wikiLinkRegex.exec(text)) !== null) {
            const symbol = match[1];
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);

            // Create command URI to jump to symbol
            const commandUri = vscode.Uri.parse(
                `command:polyglot.goToSymbol?${encodeURIComponent(JSON.stringify({ symbol, uri: document.uri.toString() }))}`
            );

            const link = new vscode.DocumentLink(range, commandUri);
            link.tooltip = `Go to ${symbol}`;
            links.push(link);
        }

        return links;
    }
}
