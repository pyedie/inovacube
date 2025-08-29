import express from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";
import Redis from "ioredis";

// --- Config ---
const PUB = fs.readFileSync(process.env.JWT_PUBLIC_KEY_FILE, "utf8");
const ISS = process.env.JWT_ISSUER || "inovacube-auth";
const AUD = process.env.JWT_AUDIENCE || "inovacube-services";
const MONGO_URI = process.env.MONGO_URI;
const REDIS_URL = process.env.REDIS_URL;

// --- Clients ---
const mongo = new MongoClient(MONGO_URI);
await mongo.connect();
const db = mongo.db(); // from URI
const col = db.collection("profiles");
await col.createIndex({ mc_uuid: 1 }, { unique: true });
await col.createIndex({ username: 1 }, { unique: true });

const redis = new Redis(REDIS_URL);

// --- App ---
const app = express();
app.use(express.json());

// Tiny logs
app.use((req,res,next)=>{ const t=Date.now(); res.on("finish",()=>console.log(JSON.stringify({t:"http",m:req.method,p:req.url,s:res.statusCode,ms:Date.now()-t}))); next(); });

// Auth middleware
function requireAuth(req, res, next) {
  const h = req.headers["authorization"];
  if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "missing token" });
  try {
    req.user = jwt.verify(h.slice(7), PUB, { algorithms:["RS256"], issuer:ISS, audience:AUD });
    next();
  } catch (e) {
    return res.status(403).json({ error: "invalid token" });
  }
}

// Health
app.get("/healthz", (_req,res)=>res.json({ ok:true, service:"profiles" }));
app.get("/livez", (_req,res)=>res.send("ok"));
app.get("/readyz", async (_req,res)=>res.send("ready"));

// GET /api/v1/me -> profil par mc_uuid (créé si absent)
app.get("/api/v1/me", requireAuth, async (req, res) => {
  const mc_uuid = req.user.sub;
  let doc = await col.findOne({ mc_uuid });
  if (!doc) {
    doc = {
      mc_uuid,
      username: `Player_${mc_uuid.replace(/-/g, "").slice(0,6)}`,
      role: "player",
      createdAt: new Date().toISOString()
    };
    await col.insertOne(doc);
  }
  // presence online (TTL 5 min)
  await redis.set(`presence:${mc_uuid}`, "online", "EX", 300);
  res.json(doc);
});

// PATCH /api/v1/me { username? }
app.patch("/api/v1/me", requireAuth, async (req, res) => {
  const mc_uuid = req.user.sub;
  const { username } = req.body || {};
  if (username) {
    if (!/^[A-Za-z0-9_]{3,16}$/.test(username))
      return res.status(400).json({ error: "invalid_username" });
  }
  try {
    const upd = {};
    if (username) upd.username = username;
    if (!Object.keys(upd).length) return res.json({ ok:true });
    const r = await col.findOneAndUpdate({ mc_uuid }, { $set: upd }, { returnDocument:"after" });
    if (!r.value) return res.status(404).json({ error:"not_found" });
    return res.json(r.value);
  } catch (e) {
    if (e?.code === 11000) return res.status(409).json({ error:"username_taken" });
    throw e;
  }
});

app.listen(3002, () => console.log("profiles up on :3002"));
