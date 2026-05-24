const jwt = require('jsonwebtoken');
const config = require('../config');

module.exports = function requireJwt(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), config.jwtSecret);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalid or expired' });
  }
};
