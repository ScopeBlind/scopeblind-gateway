// Catch accidental network access from the Node demo subprocesses after npm
// installation. This test guard is not an operating-system sandbox.
const blocked = () => { throw new Error('The synthetic demo must not make network requests after installation'); };
for (const name of ['http', 'https']) {
  const module = require(`node:${name}`);
  module.request = blocked;
  module.get = blocked;
}
const net = require('node:net');
net.connect = blocked;
net.createConnection = blocked;
net.Socket.prototype.connect = blocked;
require('node:tls').connect = blocked;
globalThis.fetch = blocked;
