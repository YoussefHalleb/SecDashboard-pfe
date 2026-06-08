const express = require("express");
const adminController = require("../controllers/admin.controller");
const { authMiddleware } = require("./auth");
const requireRole = require("../middlewares/requireRole.middleware");

const router = express.Router();

router.get(
  "/users",
  authMiddleware,
  requireRole("admin"),
  adminController.listUsers,
);

router.patch(
  "/users/:id/role",
  authMiddleware,
  requireRole("admin"),
  adminController.changeUserRole,
);

router.delete(
  "/users/:id",
  authMiddleware,
  requireRole("admin"),
  adminController.deleteUser,
);

module.exports = router;
