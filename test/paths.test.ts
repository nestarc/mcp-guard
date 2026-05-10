import { describe, it, expect } from 'vitest';
import { isBroadPath, isParentTraversal } from '../src/utils/paths.js';

describe('isBroadPath', () => {
  it.each([
    '/',
    '~',
    '$HOME',
    '%USERPROFILE%',
    '/Users',
    '/home',
    '/Users/alice',
    '/home/alice',
    'C:',
    'C:\\',
    'C:/',
    'D:\\',
    'C:\\Users',
    'C:\\Users\\alice',
    'C:/Users/alice',
  ])('returns true for broad path %s', (p) => {
    expect(isBroadPath(p)).toBe(true);
  });

  it.each([
    '/Users/alice/project/docs',
    '/home/alice/code',
    'C:\\Users\\alice\\project',
    './local',
    'src',
    '',
  ])('returns false for narrow path %s', (p) => {
    expect(isBroadPath(p)).toBe(false);
  });
});

describe('isParentTraversal', () => {
  it.each(['..', '../..', '../../foo', '..\\bar'])('detects parent traversal in %s', (p) => {
    expect(isParentTraversal(p)).toBe(true);
  });

  it.each(['./foo', 'foo/..bar', 'src'])('does not flag %s', (p) => {
    expect(isParentTraversal(p)).toBe(false);
  });
});
