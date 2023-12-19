const { sign, verify } = require("jsonwebtoken");

// jwt.js
const createTokens = (user) => {
  const accessToken = sign(
    { id: user.id, username: user.username, email: user.email },
    "jwtsecretplschange"
  );
  return accessToken;
};

const validateToken = (req, res, next) => {
  const accessToken = req.cookies["access-token"];

  if (!accessToken) {
    return res.status(400).json({ error: "User not Authenticated!" });
  }

  try {
    const validToken = verify(accessToken, "jwtsecretplschange");
    console.log("Decoded Token Payload:", validToken); // Tambahkan logging di sini
    if (validToken) {
      req.authenticated = true;
      req.authData = validToken;
      return next();
    }
  } catch (err) {
    return res.status(400).json({ error: "Invalid token" });
  }
};


module.exports = { createTokens, validateToken };