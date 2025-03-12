require('dotenv').config();

const TokenHandler = require('./token-handler');

const tokenHandler = new TokenHandler(process.env.JWT_TOKEN);

function validateRequestBody(body) {
  if (!body || typeof body !== 'object') {
    return false;
  }
  return true;
}

exports.signToken = async ctx => {
  const logger = ctx.codeveros.logger;
  logger.debug('Creating token');
  const { payload } = ctx.request.body;
  if (!validateRequestBody(ctx.request.body)) {
    logger.debug('Invalid request body');
    ctx.throw(400, 'Invalid request body');
  }
  const token = await tokenHandler.sign(payload);
  logger.debug('Token created');
  ctx.body = { token };
};

exports.verifyToken = async ctx => {
  const logger = ctx.codeveros.logger;
  const values = ctx.request.body;
  logger.debug('Verifying token');
  if (!validateRequestBody(ctx.request.body)) {
    logger.debug('Invalid request body');
    ctx.throw(400, 'Invalid request body');
  }
  if (values && values.token) {
    try {
      const payload = await tokenHandler.verify(values.token);
      logger.debug('token verified');
      ctx.body = { valid: true, payload };
    } catch (err) {
      logger.debug('token invalid');
      ctx.body = { valid: false };
    }
  } else {
    logger.debug('Token information missing');
    ctx.throw(400, 'Missing token information');
  }
};
