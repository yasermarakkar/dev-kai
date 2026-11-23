import crypto from 'node:crypto';

let lastHash = null;

/**
 * Append one audit event. The actor always comes from the verified session,
 * never from the request body.
 */
export async function recordAudit(pool, req, { action, targetType, targetId, metadata }) {
  const actorId = req.user?.id ?? 'anonymous';
  const entry = { actorId, action, targetType, targetId, ip: req.ip, userAgent: req.get('user-agent'), requestId: req.id, metadata };
  const hash = crypto.createHash('sha256').update(JSON.stringify({ ...entry, prev: lastHash })).digest('hex');
  await pool.query(
    'INSERT INTO audit_log (actor_id, action, target_type, target_id, ip_address, user_agent, request_id, metadata, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
    [actorId, action, targetType, targetId, entry.ip, entry.userAgent, entry.requestId, metadata ?? null, lastHash, hash],
  );
  lastHash = hash;
}
