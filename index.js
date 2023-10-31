const jwt = require("jsonwebtoken");

// Constants.
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;

exports.handler = async (event) => {
  // Gets event header.
  const header =
    typeof event.header === "string" ? JSON.parse(event.header) : event.header;

  // Needs to be authorized by a given token.
  const token = header.token;

  // Object that stores values used by 'jsonwebtoken - verify' function call.
  const jwtSettings = {
    publicKey: JWT_PUBLIC_KEY,
    options: {
      algorithms: ["RS256"],
    },
  };

  try {
    // Verify and decode the JWT token.
    const decoded = jwt.verify(
      token,
      jwtSettings.publicKey,
      jwtSettings.options
    );

    if (decoded.sub == null) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
};
