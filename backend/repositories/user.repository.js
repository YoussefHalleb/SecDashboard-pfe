const pool = require("../db");

async function findAllUsers() {
  const { rows } = await pool.query(
    `SELECT id, email, role, created_at FROM users ORDER BY created_at DESC`,
  );

  return rows;
}

async function updateUserRole(id, role) {
  const { rows } = await pool.query(
    `UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, role`,
    [role, id],
  );

  return rows[0];
}

async function deleteUser(id) {
  await pool.query(`DELETE FROM users WHERE id = $1`, [id]);
}

module.exports = {
  findAllUsers,
  updateUserRole,
  deleteUser,
};
