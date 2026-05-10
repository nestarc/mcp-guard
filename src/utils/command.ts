const STRIP_EXT = /\.(exe|cmd|bat|ps1)$/i;

export function commandBasename(command: string): string {
  if (!command) return '';
  // Take last segment after either / or \
  let basename = command;
  const lastSep = Math.max(command.lastIndexOf('/'), command.lastIndexOf('\\'));
  if (lastSep >= 0) basename = command.slice(lastSep + 1);
  return basename.replace(STRIP_EXT, '').toLowerCase();
}
