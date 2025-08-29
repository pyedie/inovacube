import express from "express";
import jwt from "jsonwebtoken";
import fs from "fs";

const app = express();
app.use(express.json());

const PRIV = fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE, "utf8");
const PUB  = fs.readFileSync(process.env.JWT_PUBLIC_KEY_FILE, "utf8");
const TTL  = parseInt(process.env.JWT_TTL_MINUTES || "15", 10);

// simple health
app.get("/healthz", (_req, res) => res.json({ ok: true, service: "auth" }));

// échange session Mojang -> token Inova (MVP)
app.post("/auth/mc/exchange", (req, res) => {
  const { mc_uuid } = req.body || {};
  if (!mc_uuid) return res.status(400).json({ error: "mc_uuid required" });

  const nowSec = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    {
      sub: mc_uuid,
      iss: "inovacube-auth",
      aud: "inovacube-services",
      iat: nowSec,
      nbf: nowSec,
      scope: "player",
      typ: "access"
    },
    PRIV,
    { algorithm: "RS256", expiresIn: `${TTL}m`, keyid: "inova-rs256-1" }
  );

  res.json({ token, exp: (nowSec + TTL * 60) });
});

app.listen(3001, () => console.log("auth service up on :3001"));
