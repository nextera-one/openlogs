import * as fs from 'fs';
import * as path from 'path';

export function ensureDirForFile(filePath: string): void {
  const dir = path.dirname(path.resolve(filePath));
  fs.mkdirSync(dir, { recursive: true });
}

export function readJsonFile<T>(filePath: string): T {
  const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
  return JSON.parse(raw) as T;
}

export function writeJsonFile(filePath: string, value: unknown): void {
  ensureDirForFile(filePath);
  fs.writeFileSync(
    path.resolve(filePath),
    JSON.stringify(value, null, 2) + '\n',
    'utf8',
  );
}

export function readJsonLines(filePath: string): any[] {
  const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
  const lines = raw.split(/\r?\n/).filter((line: string) => line.trim().length > 0);
  return lines.map((line: string) => JSON.parse(line));
}

export function appendJsonLine(filePath: string, value: unknown): void {
  ensureDirForFile(filePath);
  fs.appendFileSync(
    path.resolve(filePath),
    JSON.stringify(value) + '\n',
    'utf8',
  );
}
