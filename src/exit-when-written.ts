/**
 * Ending a command once its output is written.
 *
 * process.exit() ends the process at once, while Node writes to a pipe asynchronously on macOS and on Linux, so the
 * part of the output the reader had not yet taken was lost and the exit status still named the outcome. Up to 0.32.3
 * the CLI ended most commands that way: `protect-mcp report | jq` read the first 64 KiB of a larger report, with exit
 * 0, and the stdio gateway cut a large last reply short when the server it wraps exited.
 */

let exiting: Promise<never> | undefined;

/**
 * Ends the process with `code` once stdout and stderr have taken everything written to them.
 *
 * The status is set at once, as process.exitCode. The exit that follows keeps anything still open (a socket, a timer,
 * a server) from holding the process afterwards. The returned promise never settles, so `return exitWhenWritten(code)`
 * stops the caller where process.exit() did, and no `finally` block runs past it either. The first call decides the
 * status, as the first process.exit() did. A reader that has gone away (EPIPE) fails the pending write, and the run
 * still ends with its own status.
 */
export function exitWhenWritten(code: number | string = 0): Promise<never> {
  if (exiting) return exiting;
  process.exitCode = code;
  exiting = new Promise<never>(() => {
    afterWritten(process.stdout, () => afterWritten(process.stderr, () => process.exit(code)));
  });
  return exiting;
}

/** Calls `then` once `stream` has taken everything written to it so far, or once that write has failed. */
function afterWritten(stream: NodeJS.WriteStream, then: () => void): void {
  // Without a listener, a write that fails because the reader closed the pipe would end the process with an
  // 'error' event and another status.
  stream.on('error', () => {});
  try {
    stream.write('', () => then());
  } catch {
    then();
  }
}
