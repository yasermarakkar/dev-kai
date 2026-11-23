import jwt from 'jsonwebtoken';

export function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
    next();
  } catch (err) {
    req.log.warn({ err }, 'auth rejected');
    res.status(401).end();
  }
}
