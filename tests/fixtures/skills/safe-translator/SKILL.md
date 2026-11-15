---
name: safe-translator
description: Translates markdown documentation files between languages while preserving formatting.
---

# Safe Documentation Translator

This skill helps users translate markdown documentation files between different human languages.

## Workflow

1. Read the source markdown file specified by the user.
2. Identify code blocks, URLs, and markdown formatting to ensure they remain untouched during translation.
3. Translate prose paragraphs into the requested target language.
4. Save the translated content to the specified output file path.

## Rules
- Do not execute any scripts or shell commands.
- Preserve all existing code snippets and file frontmatter intact.

