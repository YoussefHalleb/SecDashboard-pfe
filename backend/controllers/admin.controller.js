const userRepository = require("../repositories/user.repository");

async function listUsers(req, res) {
  try {
    const users = await userRepository.findAllUsers();
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
}

async function changeUserRole(req, res) {
  try {
    const { role } = req.body;

    if (!["admin", "developer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const user = await userRepository.updateUserRole(req.params.id, role);
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: "Failed to update user role" });
  }
}

async function deleteUser(req, res) {
  try {
    await userRepository.deleteUser(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Delete user failed" });
  }
}

module.exports = {
  listUsers,
  changeUserRole,
  deleteUser,
};
