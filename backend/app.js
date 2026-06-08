const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const { router: authRouter } = require("./routes/auth");

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost",
      "http://localhost:80",
      "https://35.195.231.227.nip.io",
      process.env.CLIENT_ORIGIN,
    ].filter(Boolean),
    credentials: true,
  }),
);

app.use("/auth", authRouter);

app.get("/", (req, res) => {
  res.json({ ok: true, message: "Backend running" });
});

module.exports = app;
