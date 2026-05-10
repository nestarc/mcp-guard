import { readFile } from 'node:fs/promises';
import { parse, printParseErrorCode, type ParseError } from 'jsonc-parser';
import { LoadError } from '../types.js';

export async function loadConfig(filePath: string): Promise<unknown> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf-8');
  } catch (err) {
    throw new LoadError(`Could not read file: ${filePath}`, err);
  }

  const errors: ParseError[] = [];
  const data = parse(raw, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    const first = errors[0]!;
    const code = printParseErrorCode(first.error);
    throw new LoadError(
      `Failed to parse ${filePath}: ${code} at offset ${first.offset}`
    );
  }
  return data;
}
