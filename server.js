// ---------- server.js ----------
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

// NEW: JWT libs for Azure Entra (for identity only)
const { expressjwt: jwt } = require("express-jwt");
const jwks = require("jwks-rsa");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://edutalkUser:MyPass123@edutalk-cluster.n8jlomv.mongodb.net/edutalk?retryWrites=true&w=majority";

// You can keep this for emergency creator access during transition (not used for role logic)
const CREATOR_API_KEY = process.env.CREATOR_API_KEY || "";

// 🔐 Entra IDs from Azure App Service → Configuration
const TENANT_ID = process.env.TENANT_ID || "<TENANT_ID>";
const CLIENT_ID = process.env.CLIENT_ID || "<CLIENT_ID>";

// --- DB ---
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) =>
    console.error("❌ MongoDB connection error:", err?.message || err)
  );

// ----- Schemas -----
const commentSchema = new mongoose.Schema(
  {
    text: String,
    createdAt: { type: Date, default: Date.now },
    // NEW (optional metadata if user is signed in)
    userId: { type: String, default: "" }, // Entra oid
    userName: { type: String, default: "" },
  },
  { _id: false }
);

const videoSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    publisher: { type: String, default: "UNKNOWN" },
    producer: { type: String, default: "UNKNOWN" },
    genre: { type: String, default: "General" },
    age: { type: String, default: "PG" },
    playbackUrl: { type: String, required: true }, // either YT or MP4/WebM/Ogg
    external: { type: Boolean, default: false },
    comments: { type: [commentSchema], default: [] },
    ratings: { type: [Number], default: [] },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "videos" }
);

const Video = mongoose.model("Video", videoSchema);

// NEW: Users with self-managed roles
const userSchema = new mongoose.Schema(
  {
    oid: { type: String, required: true, unique: true }, // Entra user OID (or 'sub')
    email: { type: String, default: "" },
    name: { type: String, default: "" },
    role: { type: String, enum: ["Consumer", "Creator"], default: "Consumer" },
  },
  { collection: "users", timestamps: true }
);
const User = mongoose.model("User", userSchema);

// ----- Helpers -----
const dbState = () =>
  (
    [
      "disconnected",
      "connected",
      "connecting",
      "disconnecting",
    ][mongoose.connection.readyState] || "unknown"
  );

const requireCreatorApiKey = (req, res, next) => {
  if (!CREATOR_API_KEY) return next();
  if (req.headers["x-api-key"] !== CREATOR_API_KEY)
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  next();
};

const norm = (b = {}) => ({
  title: (b.title || "").trim(),
  publisher: (b.publisher || "").trim(),
  producer: (b.producer || "").trim(),
  genre: (b.genre || "").trim(),
  age: (b.age || b.ageRating || "PG").trim(),
  playbackUrl: (b.playbackUrl || b.url || "").trim(),
  external: !!b.external,
});

const expose = (v) => ({
  _id: v._id,
  title: v.title,
  publisher: v.publisher,
  producer: v.producer,
  genre: v.genre,
  age: v.age,
  playbackUrl: v.playbackUrl,
  external: !!v.external,
  comments: v.comments || [],
  ratings: v.ratings || [],
  createdAt: v.createdAt,
});

const isYouTube = (url = "") => /(?:youtube\.com|youtu\.be)/i.test(String(url));

// 🔐 JWT middleware (credentialsRequired=false so public pages still work)
const jwtCheck = jwt({
  secret: jwks.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
  }),
  audience: CLIENT_ID,
  issuer: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
  algorithms: ["RS256"],
  credentialsRequired: false,
});
app.use(jwtCheck);

// Get OID/claims from token (supports both v2 id/access tokens)
const getAuthInfo = (req) => {
  const a = req.auth || {};
  return {
    oid: a.oid || a.sub || "",
    name: a.name || a.preferred_username || a.unique_name || "",
    email:
      a.preferred_username ||
      a.upn ||
      a.email ||
      a.emails?.[0] ||
      "",
  };
};

// Ensure a user document exists (default role = Consumer)
async function ensureUser(req) {
  const { oid, name, email } = getAuthInfo(req);
  if (!oid) return null;
  let u = await User.findOne({ oid });
  if (!u) {
    u = await User.create({ oid, name, email, role: "Consumer" });
  } else {
    // light profile refresh
    const patch = {};
    if (name && name !== u.name) patch.name = name;
    if (email && email !== u.email) patch.email = email;
    if (Object.keys(patch).length) {
      await User.updateOne({ oid }, { $set: patch });
      u = await User.findOne({ oid });
    }
  }
  return u;
}

// Role guard using our DB role
function requireAppRole(role) {
  return async (req, res, next) => {
    const u = await ensureUser(req);
    if (!u) return res.status(401).json({ ok: false, error: "signin required" });
    if (u.role !== role) {
      return res
        .status(403)
        .json({ ok: false, error: `Forbidden: ${role} role required` });
    }
    next();
  };
}

// API
app.get("/health", (_req, res) => res.json({ status: "ok", db: dbState() }));

app.get("/videos", async (_req, res) => {
  try {
    const list = await Video.find().sort({ createdAt: -1 }).lean();
    res.json(list.map(expose));
  } catch (e) {
    console.error("List error:", e);
    res.status(500).json({ ok: false, error: "Failed to fetch" });
  }
});

// -------- Self-switching identities --------

// Current user profile (+auto-provision)
app.get("/me", async (req, res) => {
  const u = await ensureUser(req);
  if (!u) return res.status(401).json({ ok: false, error: "signin required" });
  res.json({
    ok: true,
    user: { oid: u.oid, email: u.email, name: u.name, role: u.role },
  });
});

// Switch role (no admin approval)
app.post("/me/role", async (req, res) => {
  const u = await ensureUser(req);
  if (!u) return res.status(401).json({ ok: false, error: "signin required" });

  const nextRole = String(req.body?.role || "").trim();
  if (!["Consumer", "Creator"].includes(nextRole)) {
    return res
      .status(400)
      .json({ ok: false, error: "role must be 'Consumer' or 'Creator'" });
  }

  if (u.role === nextRole) {
    return res.json({
      ok: true,
      user: { oid: u.oid, email: u.email, name: u.name, role: u.role },
      changed: false,
    });
  }

  await User.updateOne({ oid: u.oid }, { $set: { role: nextRole } });
  return res.json({
    ok: true,
    user: { oid: u.oid, email: u.email, name: u.name, role: nextRole },
    changed: true,
  });
});

// -------- Videos --------

// CREATE video → our app-managed Creator role
app.post("/videos", requireAppRole("Creator"), async (req, res) => {
  try {
    const data = norm(req.body);
    if (!data.title || !data.playbackUrl)
      return res
        .status(400)
        .json({ ok: false, error: "title and playbackUrl required" });
    const doc = await Video.create(data);
    res.status(201).json(expose(doc));
  } catch (e) {
    console.error("Create error:", e);
    res.status(500).json({ ok: false, error: "Failed to create" });
  }
});

// Comments (kept open so your current UI works; if signed in, we stamp user)
app.post("/videos/:id/comments", async (req, res) => {
  try {
    const t = (req.body?.text || "").trim();
    if (!t) return res.status(400).json({ ok: false, error: "text required" });

    const info = getAuthInfo(req); // may be empty if not signed in
    const payload = {
      text: t,
      createdAt: new Date(),
      userId: info.oid || "",
      userName: info.name || "",
    };

    const v = await Video.findByIdAndUpdate(
      req.params.id,
      { $push: { comments: payload } },
      { new: true }
    );
    if (!v) return res.status(404).json({ ok: false, error: "not found" });
    res.json(expose(v));
  } catch (e) {
    if (e?.name === "CastError") {
      return res.status(400).json({ ok: false, error: "invalid id" });
    }
    console.error("Comment error:", e);
    res.status(500).json({ ok: false, error: "Failed to add comment" });
  }
});

// Ratings (kept open; later we can require login and 1-per-user)
app.post("/videos/:id/ratings", async (req, res) => {
  try {
    const val = Number(req.body?.value);
    if (!Number.isFinite(val) || val < 1 || val > 5)
      return res.status(400).json({ ok: false, error: "value must be 1..5" });

    const v = await Video.findByIdAndUpdate(
      req.params.id,
      { $push: { ratings: val } },
      { new: true }
    );
    if (!v) return res.status(404).json({ ok: false, error: "not found" });
    res.json(expose(v));
  } catch (e) {
    if (e?.name === "CastError") {
      return res.status(400).json({ ok: false, error: "invalid id" });
    }
    console.error("Rating error:", e);
    res.status(500).json({ ok: false, error: "Failed to add rating" });
  }
});

/* -----------------------------
   Deletion endpoints
------------------------------*/

// delete by id → Creator only
app.delete("/videos/:id", requireAppRole("Creator"), async (req, res) => {
  try {
    const v = await Video.findByIdAndDelete(req.params.id);
    if (!v) return res.status(404).json({ ok: false, error: "not found" });
    res.json({ ok: true });
  } catch (e) {
    if (e?.name === "CastError") {
      return res.status(400).json({ ok: false, error: "invalid id" });
    }
    console.error("Delete error:", e);
    res.status(500).json({ ok: false, error: "Failed to delete" });
  }
});

// bulk purge of YouTube-linked items → Creator only
app.delete("/videos", requireAppRole("Creator"), async (req, res) => {
  try {
    if (String(req.query.provider || "").toLowerCase() !== "youtube") {
      return res
        .status(400)
        .json({
          ok: false,
          error: "unsupported bulk delete; use provider=youtube",
        });
    }
    const r = await Video.deleteMany({
      playbackUrl: { $regex: /(youtube\.com|youtu\.be)/i },
    });
    res.json({ ok: true, deleted: r.deletedCount });
  } catch (e) {
    console.error("Bulk delete error:", e);
    res.status(500).json({ ok: false, error: "Failed to purge" });
  }
});

// Static site
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

// explicit file routes BEFORE catch-all
app.get("/", (_req, res) => res.sendFile(path.join(publicDir, "index.html")));
app.get("/videos.html", (_req, res) =>
  res.sendFile(path.join(publicDir, "videos.html"))
);
app.get("/upload.html", (_req, res) =>
  res.sendFile(path.join(publicDir, "upload.html"))
);

// catch-all LAST
app.get("*", (_req, res) => res.sendFile(path.join(publicDir, "index.html")));

const server = app.listen(PORT, () =>
  console.log(`✅ Server on :${PORT}`)
);

// graceful shutdown
function shutdown(sig) {
  console.log(`\n${sig} received. Closing...`);
  server.close(async () => {
    try {
      await mongoose.disconnect();
    } catch {}
    process.exit(0);
  });
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
