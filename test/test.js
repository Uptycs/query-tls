'use strict';

const assert = require('assert');
const re = require('json-logic-js');
const index = require('..');

describe('Rules', () => {
  it('getRules()', () => {
    const rules = index.getRules();
    assert.ok(rules);
    assert.ok(Object.keys(rules).length > 0);

    Object.keys(rules).forEach(table => {
      assert.ok(table.startsWith('kubernetes_'));
      const tableRules = rules[table];
      assert.ok(Object.keys(tableRules).length > 0);
    });
  });

  it('Container resource requests/limits CPU/memory are not configured', () => {
    const rule = {
      if: [
        {
          missing: [
            'resource_limits.cpu',
            'resource_limits.memory',
            'resource_requests.cpu',
            'resource_requests.memory'
          ]
        },
        true,
        false
      ]
    };
    assert.strictEqual(re.apply(rule, {}), true);
    assert.strictEqual(re.apply(rule, ''), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {}}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: ''}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {cpu: '123'}}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {cpu: '123', memory: '456'}}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {cpu: '123', memory: '456'}, resource_requests: {}}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {cpu: '123', memory: '456'}, resource_requests: {cpu: '123'}}), true);
    assert.strictEqual(re.apply(rule, {resource_limits: {cpu: '123', memory: '456'}, resource_requests: {cpu: '123', memory: '456'}}), false);
  });

  it('Container drop capabilities does not include ALL', () => {
    const rule = { '!': { in: ['all', { var: 'capabilities_drop' }] } };
    assert.strictEqual(re.apply(rule, {}), true);
    assert.strictEqual(re.apply(rule, ''), true);
    assert.strictEqual(re.apply(rule, {capabilities_drop: ''}), true);
    assert.strictEqual(re.apply(rule, {capabilities_drop: ['']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_drop: ['abc', 'def', '']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_drop: ['abc', 'def', 'all']}), false);
  });

  it('Container using capabilities that allow privilege escalation', () => {
    const rule = {
      or: [
        {in: ['SYS_ADMIN', {var: 'capabilities_add'}]},
        {in: ['SYS_PTRACE', {var: 'capabilities_add'}]},
        {in: ['SYS_MODULE', {var: 'capabilities_add'}]},
        {in: ['DAC_READ_SEARCH', {var: 'capabilities_add'}]},
        {in: ['DAC_OVERRIDE', {var: 'capabilities_add'}]},
        {in: ['CHOWN', {var: 'capabilities_add'}]},
        {in: ['FORMER', {var: 'capabilities_add'}]},
        {in: ['SETUID', {var: 'capabilities_add'}]},
        {in: ['SETGID', {var: 'capabilities_add'}]},
        {in: ['SETFCAP', {var: 'capabilities_add'}]},
        {in: ['KILL', {var: 'capabilities_add'}]},
        {in: ['NET_BIND_SERVICE', {var: 'capabilities_add'}]},
        {in: ['NET_RAW', {var: 'capabilities_add'}]},
        {in: ['LINUX_IMMUTABLE', {var: 'capabilities_add'}]},
        {and: [
          {in: ['NET_ADMIN', {var: 'capabilities_add'}]},
          {in: ['NET_RAW', {var: 'capabilities_add'}]}
        ]}
      ]
    };
    assert.strictEqual(re.apply(rule, {}), false);
    assert.strictEqual(re.apply(rule, ''), false);
    assert.strictEqual(re.apply(rule, {capabilities_add: ''}), false);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['']}), false);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', 'def', '']}), false);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'NET_ADMIN']}), false);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', 'def', 'SYS_ADMIN']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'SYS_PTRACE']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'SYS_MODULE']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'DAC_READ_SEARCH']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'DAC_OVERRIDE']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'CHOWN']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'FORMER']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'SETUID']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'SETGID']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'SETFCAP']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'KILL']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'NET_BIND_SERVICE']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'NET_RAW']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'LINUX_IMMUTABLE']}), true);
    assert.strictEqual(re.apply(rule, {capabilities_add: ['abc', '', 'NET_RAW', 'NET_ADMIN']}), true);
  });

  it('Privileged container', () => {
    const rule = { '==': [{ var: 'privileged' }, '1'] };
    assert.strictEqual(re.apply(rule, {}), false);
    assert.strictEqual(re.apply(rule, ''), false);
    assert.strictEqual(re.apply(rule, {privileged: ''}), false);
    assert.strictEqual(re.apply(rule, {privileged: '0'}), false);
    assert.strictEqual(re.apply(rule, {privileged: 0}), false);
    assert.strictEqual(re.apply(rule, {privileged: '1'}), true);
    assert.strictEqual(re.apply(rule, {privileged: 1}), true);
  });

  it('Container root file system is not read-only', () => {
    const rule = { '!=': [{ var: 'read_only_root_filesystem' }, '1'] };
    assert.strictEqual(re.apply(rule, {}), true);
    assert.strictEqual(re.apply(rule, ''), true);
    assert.strictEqual(re.apply(rule, {read_only_root_filesystem: ''}), true);
    assert.strictEqual(re.apply(rule, {read_only_root_filesystem: '0'}), true);
    assert.strictEqual(re.apply(rule, {read_only_root_filesystem: 0}), true);
    assert.strictEqual(re.apply(rule, {read_only_root_filesystem: '1'}), false);
    assert.strictEqual(re.apply(rule, {read_only_root_filesystem: 1}), false);
  });

  it('Container is not configured to run as non-root user', () => {
    const rule = { '!=': [{ var: 'run_as_non_root' }, '1'] };
    assert.strictEqual(re.apply(rule, {}), true);
    assert.strictEqual(re.apply(rule, ''), true);
    assert.strictEqual(re.apply(rule, {run_as_non_root: ''}), true);
    assert.strictEqual(re.apply(rule, {run_as_non_root: '0'}), true);
    assert.strictEqual(re.apply(rule, {run_as_non_root: 0}), true);
    assert.strictEqual(re.apply(rule, {run_as_non_root: '1'}), false);
    assert.strictEqual(re.apply(rule, {run_as_non_root: 1}), false);
  });

  it('Container UID value should be high to avoid conflict with host UIDs', () => {
    const rule = { '<': [{ var: 'run_as_user' }, '10000'] };
    assert.strictEqual(re.apply(rule, {}), true);
    assert.strictEqual(re.apply(rule, ''), true);
    assert.strictEqual(re.apply(rule, {run_as_user: ''}), true);
    assert.strictEqual(re.apply(rule, {run_as_user: '0'}), true);
    assert.strictEqual(re.apply(rule, {run_as_user: 0}), true);
    assert.strictEqual(re.apply(rule, {run_as_user: '1'}), true);
    assert.strictEqual(re.apply(rule, {run_as_user: 1}), true);
    assert.strictEqual(re.apply(rule, {run_as_user: '10000'}), false);
    assert.strictEqual(re.apply(rule, {run_as_user: 10000}), false);
  });

  it('Container using hosts IPC, network or PID namespace', () => {
    const rule = {
      or: [
        {'==' : [{var: 'host_network'}, '1']},
        {'==' : [{var: 'host_ipc'}, '1']},
        {'==' : [{var: 'host_pid'}, '1']}
      ]
    };
    assert.strictEqual(re.apply(rule, {}), false);
    assert.strictEqual(re.apply(rule, ''), false);
    assert.strictEqual(re.apply(rule, {host_network: ''}), false);
    assert.strictEqual(re.apply(rule, {host_network: '', host_ipc: 0, host_pid: '0'}), false);
    assert.strictEqual(re.apply(rule, {host_network: 1, host_ipc: 0, host_pid: '0'}), true);
    assert.strictEqual(re.apply(rule, {host_network: '', host_ipc: '1', host_pid: '0'}), true);
    assert.strictEqual(re.apply(rule, {host_network: '', host_ipc: '0', host_pid: 1}), true);
    assert.strictEqual(re.apply(rule, {host_network: '1', host_ipc: '0', host_pid: 1}), true);
  });
});
