/** @format */

import "dotenv/config";
import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth.js";

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET is not set. Copy .env.example to .env and set it.");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/auth", authRoutes);

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  console.error(err);
  res
    .status(err.status || 500)
    .json({ error: err.status ? err.message : "Internal server error" });
});

const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log(`Auth API listening on http://localhost:${port}`)
);
