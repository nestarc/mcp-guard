import { describe, it, expect } from 'vitest';
import { commandBasename } from '../src/utils/command.js';

describe('commandBasename', () => {
  it('returns command itself when no path', () => {
    expect(commandBasename('bash')).toBe('bash');
  });

  it('strips POSIX directory', () => {
    expect(commandBasename('/usr/bin/bash')).toBe('bash');
  });

  it('strips Windows directory (backslash)', () => {
    expect(commandBasename('C:\\Program Files\\Git\\bin\\bash.exe')).toBe('bash');
  });

  it('strips Windows directory (forward slash)', () => {
    expect(commandBasename('C:/Windows/System32/cmd.exe')).toBe('cmd');
  });

  it('removes .exe extension', () => {
    expect(commandBasename('powershell.exe')).toBe('powershell');
  });

  it('removes .cmd extension', () => {
    expect(commandBasename('npm.cmd')).toBe('npm');
  });

  it('removes .bat extension', () => {
    expect(commandBasename('foo.bat')).toBe('foo');
  });

  it('removes .ps1 extension', () => {
    expect(commandBasename('script.ps1')).toBe('script');
  });

  it('lowercases for case-insensitive matching', () => {
    expect(commandBasename('BASH')).toBe('bash');
    expect(commandBasename('PowerShell.EXE')).toBe('powershell');
  });

  it('handles empty input', () => {
    expect(commandBasename('')).toBe('');
  });
});
