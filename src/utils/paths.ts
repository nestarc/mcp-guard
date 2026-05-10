const EXACT_BROAD = new Set(['/', '~', '$HOME', '%USERPROFILE%', '/Users', '/Users/', '/home', '/home/']);

const POSIX_HOME_USER_RE = /^\/(Users|home)\/[^/]+\/?$/;
const WINDOWS_DRIVE_ROOT_RE = /^[a-zA-Z]:[\\/]?$/;
const WINDOWS_USERS_RE = /^[a-zA-Z]:[\\/]Users[\\/]?$/i;
const WINDOWS_USERS_USER_RE = /^[a-zA-Z]:[\\/]Users[\\/][^\\/]+[\\/]?$/i;

export function isBroadPath(arg: string): boolean {
  if (!arg) return false;
  if (EXACT_BROAD.has(arg)) return true;
  if (POSIX_HOME_USER_RE.test(arg)) return true;
  if (WINDOWS_DRIVE_ROOT_RE.test(arg)) return true;
  if (WINDOWS_USERS_RE.test(arg)) return true;
  if (WINDOWS_USERS_USER_RE.test(arg)) return true;
  return false;
}

export function isParentTraversal(arg: string): boolean {
  if (!arg) return false;
  // Match a leading or standalone .. token
  return /^\.\.(?:[\\/]|$)/.test(arg) || arg.split(/[\\/]/).some((seg) => seg === '..');
}
