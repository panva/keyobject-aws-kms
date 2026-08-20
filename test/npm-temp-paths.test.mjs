import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import {
  chmodSync,
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  isMainThread,
  parentPort,
  threadId,
  Worker,
  workerData,
} from 'node:worker_threads';

const fixturePath = new URL(import.meta.url);
const childMarker = '--npm-temp-child';
const operationTimeout = 30_000;
const activeChildren = new Set();
const activeWorkers = new Set();

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function mode(stat) {
  return stat.mode & 0o7777;
}

function inspectFile(path) {
  const stat = lstatSync(path);
  return {
    path,
    mode: mode(stat),
    regular: stat.isFile(),
    symlink: stat.isSymbolicLink(),
    nlink: stat.nlink,
    size: stat.size,
    digest: stat.isFile() ? sha256(readFileSync(path)) : undefined,
  };
}

function serialiseError(error) {
  return {
    name: error?.name,
    code: error?.code,
    message: error?.message ?? String(error),
    stack: error?.stack,
  };
}

async function snapshotRuntime(coreEntry) {
  const runtime = await import(pathToFileURL(coreEntry).href);
  const firstModule = runtime.modulePath();
  const secondModule = runtime.modulePath();
  const firstConfig = runtime.opensslConfigPath();
  const secondConfig = runtime.opensslConfigPath();
  const privateDirectory = dirname(firstConfig);
  const directoryStat = lstatSync(privateDirectory);
  const rendezvousRoot = dirname(privateDirectory);
  const rendezvousStat = lstatSync(rendezvousRoot);
  const configText = readFileSync(firstConfig, 'utf8');

  return {
    pid: process.pid,
    threadId,
    module: inspectFile(firstModule),
    moduleStable: firstModule === secondModule,
    config: inspectFile(firstConfig),
    configStable: firstConfig === secondConfig,
    privateDirectory,
    privateDirectoryMode: mode(directoryStat),
    privateDirectoryIsDirectory: directoryStat.isDirectory(),
    privateDirectoryIsSymlink: directoryStat.isSymbolicLink(),
    rendezvousRoot,
    rendezvousRootMode: mode(rendezvousStat),
    rendezvousRootIsDirectory: rendezvousStat.isDirectory(),
    rendezvousRootIsSymlink: rendezvousStat.isSymbolicLink(),
    configContainsTemplateToken: configText.includes('$ENV::AWSKMS_MODULE'),
    configContainsModuleBasename: configText.includes(basename(firstModule)),
  };
}

function precreateRuntimeDirectory(tmpDirectory) {
  const identity = `${process.pid}-${sha256(Buffer.from(
    `${process.pid}\0${performance.timeOrigin}`,
    'utf8',
  ))}`;
  const root = join(tmpDirectory, `keyobject-aws-kms-${process.getuid()}`);
  const directory = join(root, `runtime-${identity}-ABC123`);
  const marker = join(root, `process-${identity}.path`);
  const config = join(directory, 'awskms.cnf');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  writeFileSync(marker, basename(directory), { flag: 'wx', mode: 0o400 });
  chmodSync(marker, 0o400);
  return config;
}

function precreateRuntimeConfig(tmpDirectory, fileMode = 0o600) {
  const config = precreateRuntimeDirectory(tmpDirectory);
  writeFileSync(config, 'incomplete publication', { flag: 'wx', mode: 0o600 });
  chmodSync(config, fileMode);
  return config;
}

async function expectMutationFailure(coreEntry, mutation) {
  const runtime = await import(pathToFileURL(coreEntry).href);
  const config = runtime.opensslConfigPath();
  const directory = dirname(config);
  let restore;

  switch (mutation) {
    case 'directory-mode':
      chmodSync(directory, 0o755);
      restore = () => chmodSync(directory, 0o700);
      break;
    case 'config-mode':
      chmodSync(config, 0o600);
      restore = () => chmodSync(config, 0o400);
      break;
    case 'directory-symlink': {
      const saved = `${directory}.saved`;
      renameSync(directory, saved);
      symlinkSync(saved, directory, 'dir');
      restore = () => {
        unlinkSync(directory);
        renameSync(saved, directory);
      };
      break;
    }
    case 'config-symlink': {
      const saved = `${config}.saved`;
      renameSync(config, saved);
      symlinkSync(saved, config, 'file');
      restore = () => {
        unlinkSync(config);
        renameSync(saved, config);
      };
      break;
    }
    case 'config-content': {
      const original = readFileSync(config);
      const changed = Buffer.from(original);
      changed[0] ^= 1;
      chmodSync(config, 0o600);
      writeFileSync(config, changed);
      chmodSync(config, 0o400);
      restore = () => {
        chmodSync(config, 0o600);
        writeFileSync(config, original);
        chmodSync(config, 0o400);
      };
      break;
    }
    case 'module-content': {
      const module = runtime.modulePath();
      assert.equal(dirname(module), directory, 'module-content requires an archive copy');
      const original = readFileSync(module);
      const changed = Buffer.from(original);
      changed[0] ^= 1;
      chmodSync(module, 0o700);
      writeFileSync(module, changed);
      chmodSync(module, 0o500);
      restore = () => {
        chmodSync(module, 0o700);
        writeFileSync(module, original);
        chmodSync(module, 0o500);
      };
      break;
    }
    default:
      throw new Error(`unknown mutation: ${mutation}`);
  }

  try {
    runtime.opensslConfigPath();
  } catch (error) {
    return serialiseError(error);
  } finally {
    restore();
  }
  throw new Error(`${mutation} was silently accepted`);
}

async function childMain() {
  const [, , , operation, coreEntry] = process.argv;
  try {
    let value;
    if (operation === 'hang') {
      await new Promise(() => setInterval(() => {}, 60_000));
    } else if (operation === 'wait-snapshot') {
      await new Promise((resolveInput) => process.stdin.once('data', resolveInput));
      value = await snapshotRuntime(coreEntry);
    } else if (operation === 'snapshot') {
      value = await snapshotRuntime(coreEntry);
    } else if (operation === 'retry-abandoned-publication') {
      const runtime = await import(pathToFileURL(coreEntry).href);
      const module = runtime.modulePath();
      if (module.includes('.zip/')) {
        throw new Error('abandoned-publication fixture requires a direct module path');
      }
      const pendingConfig = precreateRuntimeConfig(process.env.TMPDIR);
      const originalLstatSync = fs.lstatSync;
      let abandoned = false;
      fs.lstatSync = (...args) => {
        const stat = originalLstatSync(...args);
        if (!abandoned && args[0] === pendingConfig) {
          unlinkSync(pendingConfig);
          abandoned = true;
        }
        return stat;
      };
      syncBuiltinESMExports();
      let config;
      try {
        config = runtime.opensslConfigPath();
      } finally {
        fs.lstatSync = originalLstatSync;
        syncBuiltinESMExports();
      }
      if (!abandoned) {
        throw new Error('runtime did not inspect the abandoned publication');
      }
      if (config !== pendingConfig) {
        throw new Error('runtime did not retry the abandoned publication path');
      }
      value = await snapshotRuntime(coreEntry);
    } else if (operation === 'retain-published-metadata-failure') {
      const runtime = await import(pathToFileURL(coreEntry).href);
      const module = runtime.modulePath();
      if (module.includes('.zip/')) {
        throw new Error('metadata-failure fixture requires a direct module path');
      }
      const expectedConfig = precreateRuntimeDirectory(process.env.TMPDIR);
      const originalFsyncSync = fs.fsyncSync;
      const originalOpenSync = fs.openSync;
      let configFd;
      let configSyncs = 0;
      let injected = false;
      fs.openSync = (...args) => {
        const fd = originalOpenSync(...args);
        if (args[0] === expectedConfig) configFd = fd;
        return fd;
      };
      fs.fsyncSync = (fd) => {
        if (fd === configFd && ++configSyncs === 2) {
          injected = true;
          const error = new Error('injected metadata sync failure after publication');
          error.code = 'EIO';
          throw error;
        }
        return originalFsyncSync(fd);
      };
      syncBuiltinESMExports();
      let failure;
      try {
        runtime.opensslConfigPath();
      } catch (error) {
        failure = serialiseError(error);
      } finally {
        fs.openSync = originalOpenSync;
        fs.fsyncSync = originalFsyncSync;
        syncBuiltinESMExports();
      }
      if (!injected || failure === undefined) {
        throw new Error('runtime did not surface the injected metadata sync failure');
      }
      let publishedInode;
      try {
        publishedInode = lstatSync(expectedConfig).ino;
      } catch (cause) {
        throw new Error('runtime removed the completed publication', { cause });
      }
      const config = runtime.opensslConfigPath();
      if (config !== expectedConfig) {
        throw new Error('runtime did not retain the completed publication');
      }
      if (lstatSync(config).ino !== publishedInode) {
        throw new Error('runtime replaced the completed publication');
      }
      value = { failure, snapshot: await snapshotRuntime(coreEntry) };
    } else if (operation === 'reject-invalid-publication-mode') {
      const runtime = await import(pathToFileURL(coreEntry).href);
      runtime.modulePath();
      precreateRuntimeConfig(process.env.TMPDIR, 0o601);
      try {
        runtime.opensslConfigPath();
        value = { code: 'SILENT' };
      } catch (error) {
        value = serialiseError(error);
      }
    } else if (operation === 'worker-batch') {
      value = await Promise.all(Array.from(
        { length: 32 },
        () => runWorker(coreEntry, process.env.TMPDIR),
      ));
    } else if (operation === 'snapshot-error') {
      try {
        await snapshotRuntime(coreEntry);
        value = { code: 'SILENT' };
      } catch (error) {
        value = serialiseError(error);
      }
    } else if (operation.startsWith('mutate:')) {
      value = await expectMutationFailure(coreEntry, operation.slice('mutate:'.length));
    } else {
      throw new Error(`unknown child operation: ${operation}`);
    }
    process.stdout.write(`${JSON.stringify({ ok: true, value })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, error: serialiseError(error) })}\n`);
    process.exitCode = 1;
  }
}

async function workerMain() {
  try {
    if (workerData.operation === 'hang') {
      await new Promise(() => setInterval(() => {}, 60_000));
    } else if (workerData.operation === 'report-then-hang') {
      parentPort.postMessage({ ok: true, value: 'reported-before-hang' });
      await new Promise(() => setInterval(() => {}, 60_000));
    }
    process.env.TMPDIR = workerData.tmpDirectory;
    const value = await snapshotRuntime(workerData.coreEntry);
    parentPort.postMessage({ ok: true, value });
  } catch (error) {
    parentPort.postMessage({ ok: false, error: serialiseError(error) });
  } finally {
    parentPort.close();
  }
}

function runChild(
  operation,
  coreEntry,
  tmpDirectory,
  prepare,
  timeout = operationTimeout,
) {
  return new Promise((resolveChild, rejectChild) => {
    const needsPreparation = prepare !== undefined;
    const child = spawn(
      process.execPath,
      [fileURLToPath(fixturePath), childMarker, operation, coreEntry],
      {
        env: { ...process.env, TMPDIR: tmpDirectory },
        stdio: [needsPreparation ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      },
    );
    activeChildren.add(child);
    let stdout = '';
    let stderr = '';
    let preparationError;
    let settled = false;
    let timedOut = false;
    const settle = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeout);
    timer.unref();

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => {
      clearTimeout(timer);
      activeChildren.delete(child);
      settle(rejectChild, error);
    });
    if (needsPreparation) {
      child.on('spawn', async () => {
        try {
          await prepare(child.pid);
          if (!timedOut && !settled) child.stdin.end('\n');
        } catch (error) {
          preparationError = error;
          child.kill('SIGKILL');
        }
      });
    }
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      activeChildren.delete(child);
      if (timedOut) {
        settle(rejectChild, new Error(
          `child operation ${JSON.stringify(operation)} timed out after ${timeout}ms ` +
          `(pid=${child.pid}, code=${code}, signal=${signal})\n` +
          `stdout:\n${stdout.trim()}\nstderr:\n${stderr.trim()}`,
        ));
        return;
      }
      if (preparationError !== undefined) {
        settle(rejectChild, preparationError);
        return;
      }
      const output = stdout.trim();
      let result;
      try {
        result = JSON.parse(output);
      } catch (error) {
        settle(rejectChild, new Error(
          `child produced invalid JSON (code=${code}, signal=${signal}): ${output}\n${stderr}`,
          { cause: error },
        ));
        return;
      }
      if (code !== 0 || !result.ok) {
        const reportedError = JSON.stringify(result.error);
        settle(rejectChild, new Error(
          `child failed (code=${code}, signal=${signal}): ${reportedError}\n${stderr}`,
        ));
        return;
      }
      settle(resolveChild, result.value);
    });
  });
}

function runWorker(
  coreEntry,
  tmpDirectory,
  { operation = 'snapshot', timeout = operationTimeout } = {},
) {
  return new Promise((resolveWorker, rejectWorker) => {
    const worker = new Worker(fixturePath, {
      workerData: { awskmsTempWorker: true, coreEntry, tmpDirectory, operation },
    });
    activeWorkers.add(worker);
    const workerId = worker.threadId;
    let result;
    let settled = false;
    const settle = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeWorkers.delete(worker);
      callback(value);
    };
    const settleResult = () => {
      if (!result.ok) {
        settle(rejectWorker, new Error(`worker failed: ${JSON.stringify(result.error)}`));
      } else {
        settle(resolveWorker, result.value);
      }
    };
    const timer = setTimeout(() => {
      settle(rejectWorker, new Error(
        `worker ${workerId} operation ${JSON.stringify(operation)} timed out after ${timeout}ms`,
      ));
      worker.unref();
      void worker.terminate().catch(() => {});
    }, timeout);
    timer.unref();

    worker.once('message', (message) => {
      result = message;
      /* The result proves the Worker completed the operation under test. Do not
       * depend on incidental loader handles closing by themselves afterward. */
      settleResult();
      worker.unref();
      void worker.terminate().catch(() => {});
    });
    worker.once('error', (error) => {
      settle(rejectWorker, error);
      worker.unref();
      void worker.terminate().catch(() => {});
    });
    worker.on('exit', (code) => {
      activeWorkers.delete(worker);
      if (settled) return;
      if (result !== undefined) return;
      if (code !== 0) {
        settle(rejectWorker, new Error(`worker ${workerId} exited with code ${code}`));
      } else {
        settle(rejectWorker, new Error(`worker ${workerId} exited without reporting a result`));
      }
    });
  });
}

function assertRuntimeSnapshot(snapshot, tmpDirectory) {
  assert.equal(snapshot.moduleStable, true);
  assert.equal(snapshot.configStable, true);
  assert.equal(snapshot.privateDirectoryIsDirectory, true);
  assert.equal(snapshot.privateDirectoryIsSymlink, false);
  assert.equal(snapshot.privateDirectoryMode, 0o700);
  assert.equal(snapshot.rendezvousRootIsDirectory, true);
  assert.equal(snapshot.rendezvousRootIsSymlink, false);
  assert.equal(snapshot.rendezvousRootMode, 0o700);
  assert.equal(snapshot.rendezvousRoot,
    join(tmpDirectory, `keyobject-aws-kms-${process.getuid()}`));
  assert.equal(dirname(snapshot.rendezvousRoot), tmpDirectory);
  assert.equal(snapshot.config.mode, 0o400);
  assert.equal(snapshot.config.regular, true);
  assert.equal(snapshot.config.symlink, false);
  assert.equal(snapshot.config.nlink, 1);
  assert.equal(snapshot.configContainsTemplateToken, false);
  assert.equal(snapshot.configContainsModuleBasename, true);
  assert.equal(snapshot.config.path, join(snapshot.privateDirectory, 'awskms.cnf'));
}

function createPrecreatedEntries(tmpDirectory, pid) {
  const rendezvousRoot = join(tmpDirectory, `keyobject-aws-kms-${process.getuid()}`);
  mkdirSync(rendezvousRoot, { mode: 0o700 });
  chmodSync(rendezvousRoot, 0o700);
  const prefix = join(rendezvousRoot, `runtime-${pid}`);
  const legacy = prefix;
  const safeDirectory = `${prefix}-AAAAAA`;
  const unsafeDirectory = `${prefix}-BBBBBB`;
  const regularFile = `${prefix}-CCCCCC`;
  const symlink = `${prefix}-DDDDDD`;
  const symlinkTarget = join(tmpDirectory, `attacker-target-${pid}`);
  const sentinels = new Map([
    [join(legacy, 'awskms.cnf'), 'legacy-predictable-directory'],
    [join(safeDirectory, 'awskms.cnf'), 'precreated-safe-mode-directory'],
    [join(unsafeDirectory, 'awskms.cnf'), 'precreated-wrong-mode-directory'],
    [join(symlinkTarget, 'awskms.cnf'), 'symlink-target-directory'],
  ]);

  for (const directory of [legacy, safeDirectory, unsafeDirectory, symlinkTarget]) {
    mkdirSync(directory, { mode: 0o700 });
  }
  chmodSync(legacy, 0o700);
  chmodSync(safeDirectory, 0o700);
  chmodSync(unsafeDirectory, 0o777);
  chmodSync(symlinkTarget, 0o700);
  for (const [path, contents] of sentinels) writeFileSync(path, contents, { mode: 0o600 });
  writeFileSync(regularFile, 'precreated-regular-file', { mode: 0o600 });
  symlinkSync(symlinkTarget, symlink, 'dir');

  return {
    rendezvousRoot,
    legacy,
    safeDirectory,
    unsafeDirectory,
    regularFile,
    symlink,
    symlinkTarget,
    sentinels,
  };
}

function assertPrecreatedEntriesUnchanged(entries) {
  assert.equal(mode(lstatSync(entries.rendezvousRoot)), 0o700);
  assert.equal(mode(lstatSync(entries.legacy)), 0o700);
  assert.equal(mode(lstatSync(entries.safeDirectory)), 0o700);
  assert.equal(mode(lstatSync(entries.unsafeDirectory)), 0o777);
  assert.equal(lstatSync(entries.regularFile).isFile(), true);
  assert.equal(readFileSync(entries.regularFile, 'utf8'), 'precreated-regular-file');
  assert.equal(lstatSync(entries.symlink).isSymbolicLink(), true);
  assert.equal(readlinkSync(entries.symlink), entries.symlinkTarget);
  for (const [path, contents] of entries.sentinels) {
    assert.equal(readFileSync(path, 'utf8'), contents);
  }
}

async function expectIntegrityFailure(operation, coreEntry, tmpDirectory) {
  const error = await runChild(`mutate:${operation}`, coreEntry, tmpDirectory);
  assert.equal(error.code, 'ERR_AWSKMS_TEMP_INTEGRITY', `${operation}: ${error.message}`);
}

function unique(values) {
  return new Set(values).size;
}

if (!isMainThread && workerData?.awskmsTempWorker) {
  await workerMain();
} else if (process.argv[2] === childMarker) {
  await childMain();
} else {
  test('npm runtime uses private, race-safe temporary paths', { timeout: 120_000 }, async (t) => {
    const app = process.env.AWSKMS_NPM_TEST_APP;
    const target = process.env.AWSKMS_NPM_TEST_TARGET;
    const nativeModuleName = process.env.AWSKMS_NPM_TEST_MODULE;
    const testRoot = process.env.AWSKMS_NPM_TEST_ROOT;
    if (!app || !target || !nativeModuleName || !testRoot) {
      t.skip('runs from scripts/npm-pack.sh with a packed installation');
      return;
    }
    assert.ok(app, 'AWSKMS_NPM_TEST_APP is required');
    assert.ok(target, 'AWSKMS_NPM_TEST_TARGET is required');
    assert.ok(nativeModuleName, 'AWSKMS_NPM_TEST_MODULE is required');
    assert.ok(testRoot, 'AWSKMS_NPM_TEST_ROOT is required');

    const corePackage = resolve(app, 'node_modules/@keyobject/aws-kms');
    const satellitePackage = resolve(app, `node_modules/@keyobject/aws-kms-${target}`);
    const coreEntry = join(corePackage, 'index.js');
    const nativeModule = join(satellitePackage, nativeModuleName);
    assert.equal(lstatSync(coreEntry).isFile(), true);
    assert.equal(lstatSync(nativeModule).isFile(), true);

    mkdirSync(resolve(testRoot), { recursive: true, mode: 0o700 });
    chmodSync(resolve(testRoot), 0o700);
    const runRoot = mkdtempSync(join(resolve(testRoot), 'run-'));
    t.after(async () => {
      const childClosures = [...activeChildren].map((child) => new Promise((resolveClose) => {
        child.once('close', resolveClose);
        child.unref();
        if (!child.kill('SIGKILL')) resolveClose();
      }));
      for (const worker of activeWorkers) {
        activeWorkers.delete(worker);
        worker.unref();
        void worker.terminate().catch(() => {});
      }
      if (childClosures.length !== 0) {
        let cleanupTimer;
        await Promise.race([
          Promise.allSettled(childClosures),
          new Promise((resolveTimeout) => {
            cleanupTimer = setTimeout(resolveTimeout, 1_000);
          }),
        ]);
        clearTimeout(cleanupTimer);
      }
      rmSync(runRoot, { recursive: true, force: true });
    });
    const sharedTmp = join(runRoot, 'shared-tmp');
    mkdirSync(sharedTmp, { mode: 0o700 });
    chmodSync(sharedTmp, 0o1777);
    process.env.TMPDIR = sharedTmp;

    await t.test('terminates stuck child processes and Workers with context', async () => {
      await assert.rejects(
        runChild('hang', coreEntry, sharedTmp, undefined, 100),
        /child operation "hang" timed out after 100ms/,
      );
      await assert.rejects(
        runWorker(coreEntry, sharedTmp, { operation: 'hang', timeout: 100 }),
        /worker [0-9]+ operation "hang" timed out after 100ms/,
      );
      assert.equal(
        await runWorker(coreEntry, sharedTmp, {
          operation: 'report-then-hang',
          timeout: 100,
        }),
        'reported-before-hang',
      );
    });

    await t.test('recovers only from an exact abandoned publication state', async () => {
      const abandonedTmp = join(runRoot, 'abandoned-publication');
      const metadataFailureTmp = join(runRoot, 'published-metadata-failure');
      const invalidTmp = join(runRoot, 'invalid-publication');
      mkdirSync(abandonedTmp, { mode: 0o700 });
      mkdirSync(metadataFailureTmp, { mode: 0o700 });
      mkdirSync(invalidTmp, { mode: 0o700 });
      const recovered = await runChild(
        'retry-abandoned-publication',
        coreEntry,
        abandonedTmp,
      );
      assertRuntimeSnapshot(recovered, abandonedTmp);

      const retained = await runChild(
        'retain-published-metadata-failure',
        coreEntry,
        metadataFailureTmp,
      );
      assert.equal(retained.failure.code, 'ERR_AWSKMS_TEMP_INTEGRITY');
      assert.match(retained.failure.message, /Could not create private runtime file/u);
      assertRuntimeSnapshot(retained.snapshot, metadataFailureTmp);

      const rejected = await runChild(
        'reject-invalid-publication-mode',
        coreEntry,
        invalidTmp,
      );
      assert.equal(rejected.code, 'ERR_AWSKMS_TEMP_INTEGRITY');
      assert.match(rejected.message, /Private runtime file changed after creation/u);
      assert.doesNotMatch(rejected.message, /Timed out waiting/u);
    });

    await t.test('ignores precreated PID paths, symlinks, files, and sentinels', async () => {
      let entries;
      const snapshot = await runChild('wait-snapshot', coreEntry, sharedTmp, (pid) => {
        entries = createPrecreatedEntries(sharedTmp, pid);
      });
      assertRuntimeSnapshot(snapshot, sharedTmp);
      assert.match(basename(snapshot.privateDirectory),
        new RegExp(`^runtime-${snapshot.pid}-[a-f0-9]{64}-[A-Za-z0-9]{6}$`, 'u'));
      assert.notEqual(snapshot.privateDirectory, entries.legacy);
      assert.notEqual(snapshot.privateDirectory, entries.safeDirectory);
      assert.notEqual(snapshot.privateDirectory, entries.unsafeDirectory);
      assert.notEqual(snapshot.privateDirectory, entries.regularFile);
      assert.notEqual(snapshot.privateDirectory, entries.symlink);
      assertPrecreatedEntriesUnchanged(entries);
    });

    await t.test('rejects unsafe predictable rendezvous roots without clobbering', async () => {
      for (const kind of ['file', 'symlink', 'wrong-mode']) {
        const scenarioTmp = join(runRoot, `unsafe-root-${kind}`);
        mkdirSync(scenarioTmp, { mode: 0o700 });
        const root = join(scenarioTmp, `keyobject-aws-kms-${process.getuid()}`);
        const sentinel = `sentinel-${kind}`;
        let sentinelPath = root;

        if (kind === 'file') {
          writeFileSync(root, sentinel, { mode: 0o600 });
        } else if (kind === 'symlink') {
          const target = `${root}-target`;
          mkdirSync(target, { mode: 0o700 });
          sentinelPath = join(target, 'sentinel');
          writeFileSync(sentinelPath, sentinel, { mode: 0o600 });
          symlinkSync(target, root, 'dir');
        } else {
          mkdirSync(root, { mode: 0o700 });
          chmodSync(root, 0o755);
          sentinelPath = join(root, 'sentinel');
          writeFileSync(sentinelPath, sentinel, { mode: 0o600 });
        }

        const error = await runChild('snapshot-error', coreEntry, scenarioTmp);
        assert.equal(error.code, 'ERR_AWSKMS_TEMP_INTEGRITY', `${kind}: ${error.message}`);
        assert.equal(readFileSync(sentinelPath, 'utf8'), sentinel);
        if (kind === 'symlink') assert.equal(lstatSync(root).isSymbolicLink(), true);
        if (kind === 'wrong-mode') assert.equal(mode(lstatSync(root)), 0o755);
      }
    });

    await t.test('rejects changed modes, symlink replacement, and content tampering', async () => {
      for (const operation of [
        'directory-mode',
        'config-mode',
        'directory-symlink',
        'config-symlink',
        'config-content',
      ]) {
        await expectIntegrityFailure(operation, coreEntry, sharedTmp);
      }
    });

    await t.test('creates unique private paths across 32 processes', async () => {
      const snapshots = await Promise.all(Array.from(
        { length: 32 },
        () => runChild('snapshot', coreEntry, sharedTmp),
      ));
      for (const snapshot of snapshots) assertRuntimeSnapshot(snapshot, sharedTmp);
      assert.equal(unique(snapshots.map(({ pid }) => pid)), 32);
      assert.equal(unique(snapshots.map(({ privateDirectory }) => privateDirectory)), 32);
      assert.equal(unique(snapshots.map(({ config }) => config.path)), 32);
    });

    await t.test('shares one private path across 32 Workers in one process', async () => {
      const snapshots = await Promise.all(Array.from(
        { length: 32 },
        () => runWorker(coreEntry, sharedTmp),
      ));
      for (const snapshot of snapshots) assertRuntimeSnapshot(snapshot, sharedTmp);
      assert.equal(unique(snapshots.map(({ pid }) => pid)), 1);
      assert.equal(unique(snapshots.map(({ threadId }) => threadId)), 32);
      assert.equal(unique(snapshots.map(({ privateDirectory }) => privateDirectory)), 1);
      assert.equal(unique(snapshots.map(({ config }) => config.path)), 1);
    });

    await t.test(
      'copies a Yarn PnP-style archive module to a private executable file',
      async () => {
        const archiveScope = join(
          runRoot, 'yarn-cache', 'pkg-hash.zip', 'node_modules', '@keyobject');
        const archiveCore = join(archiveScope, 'aws-kms');
        const archiveSatellite = join(archiveScope, `aws-kms-${target}`);
        mkdirSync(archiveScope, { recursive: true });
        cpSync(corePackage, archiveCore, { recursive: true });
        cpSync(satellitePackage, archiveSatellite, { recursive: true });
        const archiveEntry = join(archiveCore, 'index.js');
        const archiveModule = join(archiveSatellite, nativeModuleName);
        assert.equal(archiveModule.includes('/pkg-hash.zip/'), true);
        const original = inspectFile(archiveModule);

        const snapshot = await runChild('snapshot', archiveEntry, sharedTmp);
        assertRuntimeSnapshot(snapshot, sharedTmp);
        assert.notEqual(snapshot.module.path, archiveModule);
        assert.equal(snapshot.module.path.includes('.zip/'), false);
        assert.equal(dirname(snapshot.module.path), snapshot.privateDirectory);
        assert.equal(basename(snapshot.module.path), nativeModuleName);
        assert.equal(snapshot.module.mode, 0o500);
        assert.equal(snapshot.module.regular, true);
        assert.equal(snapshot.module.symlink, false);
        assert.equal(snapshot.module.nlink, 1);
        assert.equal(snapshot.module.size, original.size);
        assert.equal(snapshot.module.digest, original.digest);
        assert.deepEqual(inspectFile(archiveModule), original);

        /* Use a fresh process because one process intentionally has one
         * authoritative config; importing a second installation with different
         * module bytes must fail integrity validation instead of replacing it. */
        const workerSnapshots = await runChild('worker-batch', archiveEntry, sharedTmp);
        for (const workerSnapshot of workerSnapshots) {
          assertRuntimeSnapshot(workerSnapshot, sharedTmp);
          assert.equal(workerSnapshot.module.path.includes('.zip/'), false);
          assert.equal(dirname(workerSnapshot.module.path), workerSnapshot.privateDirectory);
          assert.equal(workerSnapshot.module.mode, 0o500);
          assert.equal(workerSnapshot.module.digest, original.digest);
        }
        assert.equal(unique(workerSnapshots.map(({ privateDirectory }) => privateDirectory)), 1);
        assert.equal(unique(workerSnapshots.map(({ module }) => module.path)), 1);
        assert.equal(unique(workerSnapshots.map(({ config }) => config.path)), 1);

        await expectIntegrityFailure('module-content', archiveEntry, sharedTmp);
      },
    );
  });
}
