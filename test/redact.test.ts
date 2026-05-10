import { describe, it, expect } from 'vitest';
import { redactFinding, redactHome, redactHomeInText } from '../src/utils/redact.js';

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

describe('redactHomeInText', () => {
  it('redacts home path embedded in a sentence', () => {
    expect(redactHomeInText('Failed to parse /Users/alice/project/mcp.json', '/Users/alice')).toBe(
      'Failed to parse ~/project/mcp.json'
    );
  });

  it('redacts Windows home path embedded in a sentence', () => {
    expect(
      redactHomeInText(
        'Could not read file: C:\\Users\\alice\\project\\mcp.json',
        'C:\\Users\\alice'
      )
    ).toBe('Could not read file: ~\\project\\mcp.json');
  });

  it('does not redact sibling home names embedded in text', () => {
    expect(redactHomeInText('Path: /Users/alice2/project', '/Users/alice')).toBe(
      'Path: /Users/alice2/project'
    );
  });
});

describe('redactFinding', () => {
  it('redacts finding fields when present and preserves other fields', () => {
    const metadata = { source: 'fixture' };
    const finding = {
      ruleId: 'rule.home',
      severity: 'high',
      server: 'filesystem',
      title: 'Home path exposed',
      message: '/Users/alice/project/config.json',
      recommendation: '/Users/alice/project should not be exposed',
      path: '/Users/alice/project/config.json',
      metadata,
    };

    expect(redactFinding(finding, '/Users/alice')).toEqual({
      ruleId: 'rule.home',
      severity: 'high',
      server: 'filesystem',
      title: 'Home path exposed',
      message: '~/project/config.json',
      recommendation: '~/project should not be exposed',
      path: '~/project/config.json',
      metadata,
    });
  });

  it('does not add absent optional finding fields', () => {
    const result = redactFinding(
      {
        ruleId: 'rule.home',
        severity: 'low',
        server: 'filesystem',
        title: 'Home path exposed',
        message: '/Users/alice/project/config.json',
        metadata: { source: 'fixture' },
      },
      '/Users/alice'
    );

    expect(result.message).toBe('~/project/config.json');
    expect(Object.hasOwn(result, 'recommendation')).toBe(false);
    expect(Object.hasOwn(result, 'path')).toBe(false);
  });
});
