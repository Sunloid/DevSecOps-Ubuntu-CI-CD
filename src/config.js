'use strict';
const path = require('path');

// [V20] Cloud credentials committed to source control.
module.exports = {
  port: process.env.PORT || 3000,
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'data', 'app.db'),
  uploadDir: path.join(__dirname, '..', 'uploads'),

  // [V10] Hard-coded signing secret, trivially guessable.
  jwtSecret: process.env.JWT_SECRET,

  aws: {
    region: 'ap-south-1',
  },
};
