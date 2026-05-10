import { describe, it, expect } from 'vitest';
import { redactHome } from '../src/utils/redact.js';

describe('redactHome', () => {
  it('replaces POSIX home prefix with ~', () => {
    expect(redactHome('/Users/alice/project', '/Users/alice')).toBe('~/project');
  });

  it('replaces Linux home prefix with ~', () => {
    expect(redactHome('/home/alice/code/foo', '/home/alice')).toBe('~/code/foo');
  });

  it('replaces Windows home prefix with ~ (backslash)', () => {
    expect(redactHome('C:\\Users\\alice\\project', 'C:\\Users\\alice')).toBe('~\\project');
  });

  it('replaces Windows home prefix with ~ (forward slash)', () => {
    expect(redactHome('C:/Users/alice/project', 'C:\\Users\\alice')).toBe('~/project');
  });

  it('does not modify other users home', () => {
    expect(redactHome('/Users/bob/project', '/Users/alice')).toBe('/Users/bob/project');
  });

  it('does not modify POSIX sibling home prefix', () => {
    expect(redactHome('/Users/alice2/project', '/Users/alice')).toBe('/Users/alice2/project');
  });

  it('does not modify Windows sibling home prefix', () => {
    expect(redactHome('C:\\Users\\alice2\\project', 'C:\\Users\\alice')).toBe('C:\\Users\\alice2\\project');
  });

  it('replaces home exact match with ~', () => {
    expect(redactHome('/Users/alice', '/Users/alice')).toBe('~');
  });

  it('returns input unchanged when no match', () => {
    expect(redactHome('/etc/hosts', '/Users/alice')).toBe('/etc/hosts');
  });

  it('handles empty home gracefully', () => {
    expect(redactHome('/Users/alice', '')).toBe('/Users/alice');
  });
});
