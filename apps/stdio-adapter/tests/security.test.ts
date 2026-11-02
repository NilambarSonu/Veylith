import { describe, it, expect } from 'vitest';
import { validateCommand, getSafeChildEnvironment } from '../src/security.js';

describe('StdioAdapter Security Safeguards', () => {
  describe('validateCommand', () => {
    it('approves standard benign executables', () => {
      expect(validateCommand('node', ['server.js']).valid).toBe(true);
      expect(
        validateCommand('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/tmp']).valid,
      ).toBe(true);
      expect(validateCommand('/usr/bin/python3', ['tool.py']).valid).toBe(true);
    });

    it('rejects empty command', () => {
      expect(validateCommand('').valid).toBe(false);
      expect(validateCommand('   ').valid).toBe(false);
    });

    it('rejects commands containing shell metacharacters', () => {
      expect(validateCommand('node; rm -rf /').valid).toBe(false);
      expect(validateCommand('npx && echo pwned').valid).toBe(false);
      expect(validateCommand('tool | bash').valid).toBe(false);
      expect(validateCommand('tool`id`').valid).toBe(false);
      expect(validateCommand('tool$VAR').valid).toBe(false);
      expect(validateCommand('tool > /dev/null').valid).toBe(false);
      expect(validateCommand('tool\nrm -rf /').valid).toBe(false);
    });

    it('rejects naked shell execution with inline command flags', () => {
      expect(validateCommand('sh', ['-c', 'whoami']).valid).toBe(false);
      expect(validateCommand('bash', ['-c', 'curl http://evil.com']).valid).toBe(false);
      expect(validateCommand('/bin/zsh', ['-c', 'rm -rf /']).valid).toBe(false);
    });

    it('rejects arguments containing null bytes', () => {
      expect(validateCommand('node', ['script.js\0bad']).valid).toBe(false);
    });
  });

  describe('getSafeChildEnvironment', () => {
    it('strips known secret environment variables', () => {
      const customEnv = {
        META_MODEL_API_KEY: 'secret-meta-key',
        OPENAI_API_KEY: 'secret-openai-key',
        GITHUB_TOKEN: 'ghp_secret',
        MY_APP_VAR: 'benign-value',
      };

      const sanitized = getSafeChildEnvironment(customEnv);

      expect(sanitized['META_MODEL_API_KEY']).toBeUndefined();
      expect(sanitized['OPENAI_API_KEY']).toBeUndefined();
      expect(sanitized['GITHUB_TOKEN']).toBeUndefined();
      expect(sanitized['MY_APP_VAR']).toBe('benign-value');
    });

    it('inherits standard safe variables like PATH', () => {
      const sanitized = getSafeChildEnvironment();
      expect(sanitized['PATH']).toBeDefined();
    });
  });
});
