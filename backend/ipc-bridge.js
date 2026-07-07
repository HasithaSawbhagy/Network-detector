// Shared in-process event bus between Express routes and Electron main process.
// EventEmitter calls are synchronous, so request/response callbacks work safely.
const { EventEmitter } = require('events');
module.exports = new EventEmitter();
