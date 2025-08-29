import express from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL);

const app = express();
app.use(express.json());

// charge la clé publique
const PUB = fs.readFileSync(process.env.JWT_PUBLIC_KEY_FILE, "utf8");
const ISS = process.env.JWT_ISSUER || "inovacube-auth";
const AUD = process.env.JWT_AUDIENCE || "inovacube-services";

// health public
app.get("/healthz", (_req, res) => res.json({ ok: true, service: "api-gateway" }));

// ping public
app.get("/api/ping", (_req, res) => res.json({ pong: true, ts: new Date().toISOString() }));

// middleware d’auth (RS256, iss/aud strict)
function requireAuth(req, res, next) {
  const hdr = req.headers["authorization"];
  if (!hdr || !hdr.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing token" });
  }
  const token = hdr.slice("Bearer ".length);
  try {
    const payload = jwt.verify(token, PUB, {
      algorithms: ["RS256"],
      issuer: ISS,
      audience: AUD,
    });
    req.user = payload; // accessible après
    next();
  } catch (err) {
    return res.status(403).json({ error: "invalid token" });
  }
}

// ping presence (TTL 5 min)
app.post("/api/v1/heartbeat", requireAuth, async (req, res) => {
  await redis.set(`presence:${req.user.sub}`, "online", "EX", 300);
  res.json({ ok: true });
});

// route protégée d’exemple
app.get("/api/secure/me", requireAuth, (req, res) => {
  res.json({ user: { sub: req.user.sub, scope: req.user.scope, iat: req.user.iat, exp: req.user.exp } });
});

app.listen(3000, () => console.log("api-gateway up on :3000"));
