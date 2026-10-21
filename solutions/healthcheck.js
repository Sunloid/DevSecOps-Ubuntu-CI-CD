'use strict';
// The distroless image has no curl/wget, so the container healthcheck is a tiny Node script.
const http = require('node:http');
const req = http.get({ host: '127.0.0.1', port: process.env.PORT || 3000, path: '/health', timeout: 2000 },
  (res) => process.exit(res.statusCode === 200 ? 0 : 1));
req.on('timeout', () => req.destroy());
req.on('error', () => process.exit(1));
