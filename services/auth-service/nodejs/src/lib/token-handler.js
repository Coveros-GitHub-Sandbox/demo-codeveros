const jwt = require('jsonwebtoken');

module.exports = class TokenHandler {
  constructor (secret = '123') {
    this.secret = secret;
  }

  validatePayload(payload) {
    if (!payload || typeof payload !== 'object') {
      return false;
    }
    return true;
  }

  sign (payload) {
    return new Promise((resolve, reject) => {
      if (!this.validatePayload(payload)) {
        return reject(new Error('Invalid payload'));
      }
      jwt.sign(payload, this.secret, (err, token) => {
        return err ? reject(err) : resolve(token);
      });
    });
  }

  verify (token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.secret, (err, payload) => {
        if (err) {
          return reject(err);
        }
        if (!this.validatePayload(payload)) {
          return reject(new Error('Invalid payload'));
        }
        return resolve(payload);
      });
    });
  }
};
