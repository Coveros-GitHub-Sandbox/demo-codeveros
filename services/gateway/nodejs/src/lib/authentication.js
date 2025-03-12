const unirest = require('unirest');

const allowedUrls = [
  'http://auth-service-url/api/auth/signToken',
  'http://auth-service-url/api/auth/verifyToken',
  'http://user-service-url/api/user',
  'http://user-service-url/api/user/login'
];

function validateUrl(url) {
  return allowedUrls.includes(url);
}

module.exports = opts => {
  async function signToken (payload) {
    try {
      const url = `${opts.authServiceUrl}/api/auth/signToken`;
      if (!validateUrl(url)) {
        console.log('Invalid URL');
        return;
      }
      const tokenRes = await unirest
        .post(url).type('json').send({ payload });

      if (!tokenRes) {
        console.log('Did not receive a response when attempting to sign JWT token');
      } else if (tokenRes.error) {
        console.log(`Error received attempting to sign JWT token: ${tokenRes.error.status}-${tokenRes.error.message}`);
      } else if (!tokenRes.ok || !tokenRes.body || !tokenRes.body.token) {
        console.log('Failed to retrieve JWT from Auth Service');
      } else {
        return tokenRes.body.token;
      }
    } catch (err) {
      console.error('Failed to obtain JWT', err);
    }
  }

  const Authentication = {};

  Authentication.register = async (req, res) => {
    const { username } = req.body;

    const sendError = ({ status = 500, msg = 'Failed to register' } = {}) => {
      console.log(`Sending Registration Error Response: ${status} - ${msg}`);
      return res.status(status).send(msg);
    };

    console.log(`Attempting to register ${username}`);

    let createUserRes;
    try {
      const url = `${opts.userServiceUrl}/api/user`;
      if (!validateUrl(url)) {
        console.log('Invalid URL');
        return sendError();
      }
      createUserRes = await unirest.post(url).type('json').send(req.body);
    } catch (err) {
      console.error('Failed to create user record in User service: ', err);
      return sendError();
    }

    if (!createUserRes) {
      console.log('Did not receive a response when attempting to create user record');
      return sendError();
    } else if (createUserRes.error) {
      console.log('Error received attempting to create user record: ' +
        `${createUserRes.error.status}-${createUserRes.error.message}`);
      return sendError();
    } else if (!createUserRes.ok || !createUserRes.body || !createUserRes.body._id) {
      console.log('Failed attempting to create user record, did not receive the created user.');
      return sendError();
    }

    const user = createUserRes.body;
    const token = await signToken({ _id: user._id });

    if (!token) {
      return sendError({ msg: 'Created User, but unable to sign token.' });
    }

    console.log(`Registration completed for ${username}`);
    res.status(200).send({ token, user });
  };

  Authentication.login = async (req, res) => {
    const sendLoginError = () => res.status(401).send('Invalid username or password');

    const { username, password } = req.body;

    if (!username || !password) {
      console.log('login attempted, missing username or password field');
      return res.status(400).send('Missing username or password');
    }

    try {
      const url = `${opts.userServiceUrl}/api/user/login`;
      if (!validateUrl(url)) {
        console.log('Invalid URL');
        return sendLoginError();
      }
      const loginRes = await unirest
        .post(url)
        .type('json')
        .send({ username, password });

      if (!loginRes || !loginRes.ok || !loginRes.body) {
        console.log(`Failed on login: ${username}, received ${loginRes.status}`);
        return sendLoginError();
      }

      const userData = loginRes.body;

      if (!userData || !userData._id) {
        console.log(`User not returned with login for ${username}`);
        return sendLoginError();
      }

      const token = await signToken({ _id: userData._id });
      if (!token) {
        return res.status(500).send('Unable to sign token');
      }

      // return token and user information to user
      res.status(200).send({ token, user: userData });
    } catch (err) {
      console.error(`Error logging in for ${username}: `, err);
      return sendLoginError();
    }
  };

  Authentication.logout = (req, res) => {
    // call authservice invalidate token
    res.status(200).send();
  };

  Authentication.verifyToken = async (req, res, next) => {
    const sendTokenError = () => res.status(401).send('Unable to verify token');

    const authHeader = req.get('Authorization');

    if (!authHeader) {
      return sendTokenError();
    }

    const splitAuth = authHeader.split(' ');
    if (Array.isArray(splitAuth) && splitAuth.length >= 2 && splitAuth[0] === 'Bearer') {
      try {
        const url = `${opts.authServiceUrl}/api/auth/verifyToken`;
        if (!validateUrl(url)) {
          console.log('Invalid URL');
          return sendTokenError();
        }
        const tokenRes = await unirest
          .post(url)
          .type('json')
          .send({ token: splitAuth[1] });
        if (tokenRes.ok && tokenRes.body && tokenRes.body.valid) {
          req.jwtPayload = tokenRes.body.payload;
          return next();
        }
        return sendTokenError();
      } catch (err) {
        return sendTokenError();
      }
    } else {
      return sendTokenError();
    }
  };

  Authentication.loggedin = async (req, res) => {
    if (!req.jwtPayload) {
      return res.status(200).send();
    }

    try {
      const url = `${opts.userServiceUrl}/api/user/${req.jwtPayload._id}`;
      if (!validateUrl(url)) {
        console.log('Invalid URL');
        return res.status(200).send();
      }
      const userRes = await unirest.get(url);

      if (!userRes || userRes.error || !userRes.ok || !userRes.body || !userRes.body._id) {
        console.log('Failed to retrieve user from JWT');
        return res.status(200).send();
      }
      return res.status(200).send(userRes.body);
    } catch (err) {
      console.error('Error retrieving user from JWT: ', err);
    }
  };

  return Authentication;
};
