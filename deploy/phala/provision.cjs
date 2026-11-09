#!/usr/bin/env node
//
// provision.cjs — create one CVM through the Phala Cloud API, taking the steps
// `phala deploy` takes, for the one thing phala CLI 1.1.22 cannot do: pin the node.
//
// The API picks a node by its physical name, the NAME column of `phala nodes ls`
// (prod5, usw5), sent as `node`. Since 2026-11 it refuses node_id and teepod_id
// outright: "node_id and teepod_id are not supported for node selection"
// (ERR-01-011). CLI 1.1.22 can send only a numeric node_id, so `phala deploy`
// cannot pin the node. This script makes the same two calls with the same SDK
// (@phala/cloud, pinned in package.json), through its raw client.post so the body
// carries `node` as is:
//
//   1. POST /cvms/provision  the compose, the env KEYS (allowed_envs), the shape,
//                            image and node. Returns the app_id, compose_hash and
//                            the key the env is encrypted to. Creates nothing yet.
//   2. encryptEnvVars        the env VALUES, encrypted here to that key — what the
//                            CLI does; only the CVM can decrypt them.
//   3. POST /cvms            commit: this creates the CVM.
//
// It always CREATES: there is no update path in it, so it cannot upgrade an
// existing app in place (blue-green.md, "Why blue/green here is a DNS pointer
// flip"). What the CLI would add on its own and this does not: an SSH key found in
// ~/.ssh as DSTACK_AUTHORIZED_KEYS (the CLI does that unless told --no-dev-os,
// which would put an operator's key into the CVM and into allowed_envs).
//
// Usage (deploy-side.sh calls it; PHALA_CLOUD_API_KEY in the environment):
//   node provision.cjs --name N --compose FILE --env-file FILE --instance-type T \
//       --node NODE_NAME [--image IMAGE]
// The env file is deploy-side.sh's: KEY='VALUE' per line.
//
// Prints {"success":true,"vm_uuid":…,"name":…,"app_id":…} on stdout, the shape
// `phala deploy --json` prints. Errors go to stderr: the API's status and detail,
// never the request, which carries the API key.
'use strict';

const fs = require('fs');

function fail(msg) {
  process.stderr.write(`provision: ${msg}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const opts = {};
  const known = new Set(['--name', '--compose', '--env-file', '--instance-type', '--node', '--image']);
  for (let i = 0; i < argv.length; i += 2) {
    if (!known.has(argv[i])) fail(`unknown argument: ${argv[i]}`);
    if (i + 1 >= argv.length) fail(`${argv[i]} needs a value`);
    opts[argv[i].slice(2)] = argv[i + 1];
  }
  for (const k of ['name', 'compose', 'env-file', 'instance-type', 'node']) {
    if (!opts[k]) fail(`--${k} is required`);
  }
  return opts;
}

// deploy-side.sh writes KEY='VALUE' lines, values free of quotes and newlines.
function readEnv(path) {
  const envs = [];
  for (const line of fs.readFileSync(path, 'utf8').split('\n')) {
    if (line === '') continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)='(.*)'$/.exec(line);
    if (!m) fail(`${path}: a line is not KEY='VALUE'`);
    envs.push({ key: m[1], value: m[2] });
  }
  return envs;
}

// The node is its physical name (prod5): what `phala nodes ls` shows as NAME. A
// HashID (node_…, teepod_…) or a number is what the API used to take and now
// refuses, so say so here rather than after a round trip.
function nodeName(node) {
  if (/^(node|teepod)_[A-Za-z0-9]+$/.test(node) || /^[0-9]+$/.test(node)) {
    fail(`--node is ${JSON.stringify(node)}, a node id; the API now takes the node's name, such as prod5 (NAME in \`phala nodes ls\`)`);
  }
  if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(node)) fail(`--node must be a node name such as prod5, not ${JSON.stringify(node)}`);
  return node;
}

// The API's own words, without the request (and its X-API-Key header).
function describe(err) {
  const out = { message: err && err.message };
  for (const k of ['status', 'statusText', 'requestId', 'detail']) {
    if (err && err[k] !== undefined) out[k] = err[k];
  }
  return JSON.stringify(out, null, 2);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const node = nodeName(opts.node);
  if (!process.env.PHALA_CLOUD_API_KEY) fail('PHALA_CLOUD_API_KEY is not set');
  const compose = fs.readFileSync(opts.compose, 'utf8');
  const envs = readEnv(opts['env-file']);

  // Loaded here, not at the top, so a usage error needs no npm install.
  let sdk;
  try {
    sdk = require('@phala/cloud');
  } catch (err) {
    fail(`cannot load @phala/cloud: run \`npm ci\` in ${__dirname} (${err.code || err.message})`);
  }
  const { createClient, encryptEnvVars } = sdk;
  const client = createClient({ apiKey: process.env.PHALA_CLOUD_API_KEY });

  // The body `phala deploy` builds (CLI 1.1.22, without flags beyond ours): the
  // same compose_file defaults, KMS "PHALA", unlisted.
  const body = {
    name: opts.name,
    listed: false,
    instance_type: opts['instance-type'],
    kms: 'PHALA',
    node,
    compose_file: {
      name: '',
      docker_compose_file: compose,
      allowed_envs: envs.map((e) => e.key),
      public_logs: true,
      public_sysinfo: true,
      public_tcbinfo: true,
      secure_time: false,
      // The dstack gateway prepends a PROXY protocol header with the client's
      // address to connections it relays to 443 (dstack-gateway and guest OS
      // 0.5.9+). dstack-ingress requires it (ACCEPT_PROXY_PROTOCOL in
      // docker-compose.yml): without this, every connection is refused. Part of
      // app-compose, so it is measured into compose_hash with the rest.
      port_policy: { ports: [{ port: 443, pp: true }] },
    },
  };
  if (opts.image) body.image = opts.image;

  let prov;
  try {
    prov = await client.post('/cvms/provision', body);
  } catch (err) {
    fail(`provision refused:\n${describe(err)}`);
  }
  if (!prov || !prov.app_id) {
    // An on-chain KMS answers without an app_id and wants a contract deployed
    // first; this deployment uses Phala's KMS, so that is a misconfiguration.
    fail('provision returned no app_id (an on-chain KMS?); not supported here');
  }
  if (!prov.app_env_encrypt_pubkey) fail('provision returned no env encryption key');

  const encrypted = await encryptEnvVars(envs, prov.app_env_encrypt_pubkey);

  let cvm;
  try {
    cvm = await client.post('/cvms', {
      app_id: prov.app_id,
      encrypted_env: encrypted,
      compose_hash: prov.compose_hash,
    });
  } catch (err) {
    fail(`commit refused (app_id ${prov.app_id}):\n${describe(err)}`);
  }

  process.stdout.write(`${JSON.stringify({
    success: true,
    vm_uuid: cvm && cvm.vm_uuid,
    name: (cvm && cvm.name) || opts.name,
    app_id: (cvm && cvm.app_id) || prov.app_id,
  }, null, 2)}\n`);
}

main().catch((err) => fail(describe(err)));
