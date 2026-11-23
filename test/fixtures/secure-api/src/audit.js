import crypto from 'node:crypto';

/**
 * Append one audit event. The actor always comes from the verified session,
 * never from the request body. The previous hash is read from the database
 * (not process memory) so the chain stays intact across replicas.
 */
export async function recordAudit(pool, req, { action, targetType, targetId, metadata }) {
  const actorId = req.user?.id ?? 'anonymous';
  const entry = { actorId, action, targetType, targetId, ip: req.ip, userAgent: req.get('user-agent'), requestId: req.id, metadata };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE');
    const { rows } = await client.query('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1');
    const prevHash = rows[0]?.hash ?? null;
    const hash = crypto.createHash('sha256').update(JSON.stringify({ ...entry, prev: prevHash })).digest('hex');
    await client.query(
      'INSERT INTO audit_log (actor_id, action, target_type, target_id, ip_address, user_agent, request_id, metadata, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [actorId, action, targetType, targetId, entry.ip, entry.userAgent, entry.requestId, metadata ?? null, prevHash, hash],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
