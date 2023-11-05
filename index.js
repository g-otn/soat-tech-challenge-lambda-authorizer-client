const jwt = require('jsonwebtoken');

// JWT constants.
const JWT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\n${process.env.JWT_PUBLIC_KEY}\n-----END PUBLIC KEY-----`;

/**
 * @param {AWSLambda.APIGatewayRequestAuthorizerEventV2} event
 * @returns {Promise<boolean>}
 */
exports.handler = async (event) => {
  const token = event.identitySource?.[0]?.split('Bearer ')?.[1];

  if (!token) {
    console.log('Missing token');
    return { isAuthorized: false };
  }

  const jwtSettings = {
    publicKey: JWT_PUBLIC_KEY,
    options: {
      algorithms: ['RS256'],
    },
  };

  try {
    const decoded = jwt.verify(
      token,
      jwtSettings.publicKey,
      jwtSettings.options
    );

    if (decoded.sub == null) {
      console.log('Missing sub claim');
      return { isAuthorized: false };
    }

    return { isAuthorized: true };
  } catch (error) {
    console.log('Token validation failed', token);
    return { isAuthorized: false };
  }
};
