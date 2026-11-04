import "dotenv/config";
console.log("JWT_SECRET loaded?", !!process.env.JWT_SECRET);
import express from "express";
import { OAuth2Client } from "google-auth-library";
import mongoose from "mongoose";
import cors from "cors";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dns from "dns/promises";
import multer from "multer";
import net from "net";
import { v2 as cloudinary } from "cloudinary";
const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.use(cors());
app.use(express.json({ limit: "2mb" }));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
});

// ---------- User model ----------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, default: "", trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        password: {
      type: String,
      required: function () { return !this.googleId; },
    },
    googleId: { type: String, index: true },
    workspace: { type: String, default: "My Workspace" },
    avatar: { type: String, default: "" },
    workspaceOwner: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    workspaceRole: { type: String, enum: ["Admin", "Developer", "Viewer"], default: "Viewer" },
    workspaceJoinedAt: { type: Number, default: null },
    prefs: {
      theme: { type: String, enum: ["dark", "light"], default: "dark" },
      logsPausedAt: { type: Number, default: null },
      monitorInterval: { type: Number, default: 30 },
      monitorPaused: { type: Boolean, default: false },
    },
    resetOtpHash: String,
    resetOtpExpires: Date,
    resetOtpAttempts: { type: Number, default: 0 },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

// ---------- Request log model ----------
const requestSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  method: { type: String, default: "GET" },
  path: { type: String, default: "" },
  status: { type: Number, default: 0 },
  duration: { type: Number, default: 0 },
  api: { type: String, default: "Request tester" },
  region: { type: String, default: "local" },
  ts: { type: Number, default: () => Date.now() },
});
const RequestLog = mongoose.model("RequestLog", requestSchema);
const logOut = (r) => ({
  id: r._id.toString(),
  method: r.method,
  path: r.path,
  status: r.status,
  duration: r.duration,
  api: r.api,
  region: r.region,
  ts: r.ts,
});

const sign = (user) =>
  jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
const publicUser = (u) => ({
  id: u._id,
  name: u.name,
  email: u.email,
  workspace: u.workspace,
  avatar: u.avatar || "",
    prefs: {
    theme: u.prefs?.theme || "dark",
    logsPausedAt: u.prefs?.logsPausedAt ?? null,
    monitorInterval: u.prefs?.monitorInterval || 30,
    monitorPaused: !!u.prefs?.monitorPaused,
    ackedAlerts: u.prefs?.ackedAlerts || [],
    seenAlerts: u.prefs?.seenAlerts || [],
  },
});
const sendResetEmail = async (to, otp) => {
  // Brevo key nahi hai to OTP terminal me print hoga (dev ke liye)
  if (!process.env.BREVO_API_KEY) {
    console.log("RESET OTP:", otp);
    return;
  }

  const digits = otp
  .split("")
  .map(
    (d) =>
      `<td style="width:46px;height:56px;background:#0f1118;border:1px solid #2f5f66;border-radius:10px;text-align:center;font-family:'Courier New',monospace;font-size:28px;font-weight:700;color:#5ecfd2;">${d}</td><td style="width:8px;"></td>`
  )
  .join("");

  const html = `
  <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#0f1118" style="background:#0f1118;padding:40px 16px;font-family:Arial,Helvetica,sans-serif;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;">
        <tr><td style="padding-bottom:24px;font-size:26px;font-weight:700;color:#e8e8f0;">
        </td></tr>
        <tr><td bgcolor="#181b26" style="background:#181b26;border:1px solid #2a2e40;border-radius:16px;padding:36px 32px;">
          <div style="font-size:11px;letter-spacing:2px;font-weight:700;color:#7b6ef0;text-transform:uppercase;">Account recovery</div>
          <h1 style="margin:12px 0 8px;font-size:28px;line-height:1.2;color:#e8e8f0;">
            Reset your <span style="color:#7b6ef0;">password.</span>
          </h1>
          <p style="margin:0 0 28px;font-size:15px;line-height:1.6;color:#9a9db0;">
            Use this one-time code to set a new password. It expires in 10 minutes.
          </p>
          <table cellpadding="0" cellspacing="0" align="center"><tr>${digits}</tr></table>
          <p style="margin:28px 0 0;font-size:13px;line-height:1.6;color:#7c8095;">
            Didn't request this? You can safely ignore this email. Your password won't change.
          </p>
        </td></tr>
        <tr><td style="padding-top:20px;text-align:center;font-size:12px;color:#5c6075;">
          <span>© ${new Date().getFullYear()} EasyAPI. Your APIs, always in sync.</span>
        </td></tr>
      </table>
    </td></tr>
  </table>`;

  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": process.env.BREVO_API_KEY,
      "Content-Type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      sender: { name: "EasyAPI", email: process.env.BREVO_SENDER_EMAIL },
      to: [{ email: to }],
      subject: `${otp} is your EasyAPI reset code`,
      htmlContent: html,
    }),
  });
  if (!r.ok) throw new Error(await r.text());
};
// ---------- Routes ----------
app.get("/", (req, res) => res.send("API running"));

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, workspace } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: "This email is already registered" });

    const hashed = await bcrypt.hash(password, 10);
const user = await User.create({ name, email, password: hashed, workspace });
    res.status(201).json({ token: sign(user), user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: (email || "").toLowerCase() });

    if (!user)
      return res.status(404).json({ message: "Account not registered" });
        if (!user.password)
      return res.status(400).json({
        message: "This account uses Google sign-in. Use 'Continue with Google'.",
      });
    const ok = await bcrypt.compare(password || "", user.password);
    if (!ok)
      return res.status(401).json({ message: "Incorrect password" });

    res.json({ token: sign(user), user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential)
      return res.status(400).json({ message: "Missing Google credential" });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const p = ticket.getPayload();
    if (!p?.email || !p.email_verified)
      return res.status(401).json({ message: "Google email not verified" });

    const email = p.email.toLowerCase();
    let user = await User.findOne({ email });

    if (!user) {
      // naya user: login ya register, kisi bhi screen se account ban jaayega
      user = await User.create({ name: p.name || "", email, googleId: p.sub });
    } else if (!user.googleId) {
      user.googleId = p.sub; // purana email/password account link ho gaya
      await user.save();
    }

    res.json({ token: sign(user), user: publicUser(user) });
  } catch (err) {
    console.error("Google auth error:", err.message);
    res.status(401).json({ message: "Google sign-in failed" });
  }
});
// ---------- Auth middleware ----------
const auth = (req, res, next) => {
   if (req.scoped) return next(); 
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Not authorized" });
  try {
    req.userId = jwt.verify(token, process.env.JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ message: "Session expired, please log in again" });
  }
};
// ---------- Workspace sharing ----------
const inviteSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  ownerName: String,
  workspace: String,
  email: { type: String, required: true, lowercase: true, trim: true, index: true },
  role: { type: String, enum: ["Admin", "Developer", "Viewer"], default: "Viewer" },
  status: { type: String, enum: ["Pending", "Accepted", "Declined"], default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});
const Invite = mongoose.model("Invite", inviteSchema);

const linkSchema = new mongoose.Schema({
  a: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  b: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  role: { type: String, enum: ["Admin", "Developer", "Viewer"], default: "Viewer" },
  createdAt: { type: Number, default: () => Date.now() },
});
const Link = mongoose.model("Link", linkSchema);
const pairQ = (x, y) => ({ $or: [{ a: x, b: y }, { a: y, b: x }] });

// Kaunsa workspace dekh rahe hain? Connected nahi to apna hi.
const resolveView = async (id, target) => {
  if (!target || String(target) === String(id) || !mongoose.isValidObjectId(target))
    return { ownerId: id, role: "Owner" };
  const link = await Link.findOne(pairQ(id, target)).lean();
  // doosre ka workspace dekhne wala hamesha view-only
  return link ? { ownerId: target, role: "Viewer" } : { ownerId: id, role: "Owner" };
};

const scope = async (req, res, next) => {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Not authorized" });
  try {
    const id = jwt.verify(token, process.env.JWT_SECRET).id;
    if (!(await User.exists({ _id: id }))) return res.status(401).json({ message: "Not authorized" });
    const view = await resolveView(id, req.headers["x-workspace"]);
    req.realId = id;
    req.userId = view.ownerId;
    req.role = view.role;
    req.scoped = true;
    if (req.role === "Viewer" && req.method !== "GET")
      return res.status(403).json({ message: "Viewers have read-only access" });
    next();
  } catch {
    res.status(401).json({ message: "Session expired, please log in again" });
  }
};
app.use(["/api/apis", "/api/monitor", "/api/requests", "/api/team"], scope);
const isOwnAvatarUrl = (url) => {
  try {
    const u = new URL(url);
    return (
      u.protocol === "https:" &&
      u.hostname === "res.cloudinary.com" &&
      u.pathname.startsWith(`/${process.env.CLOUDINARY_CLOUD_NAME}/`) &&
      url.length <= 500
    );
  } catch {
    return false;
  }
};

app.put("/api/auth/profile", auth, async (req, res) => {
  try {
    const { name, workspace, avatar } = req.body;
    const patch = {};
    if (typeof name === "string") {
      if (!name.trim()) return res.status(400).json({ message: "Name cannot be empty" });
      patch.name = name.trim();
    }
    if (typeof workspace === "string") {
      if (!workspace.trim()) return res.status(400).json({ message: "Workspace name cannot be empty" });
      patch.workspace = workspace.trim();
    }
    if (avatar === "") patch.avatar = ""; // sirf Remove ke liye, photo upload route se hi set hogi
    const user = await User.findByIdAndUpdate(req.userId, patch, { new: true });
    if (!user) return res.status(404).json({ message: "User not found" });
    pushLinked(user._id);
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/avatar", auth, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No image selected" });
    console.log("avatar upload:", req.file.mimetype, req.file.size, "bytes");
    if (!req.file.size)
      return res.status(400).json({ message: "This file is empty. Choose another photo." });
    if (!/^image\/(png|jpe?g|webp)$/.test(req.file.mimetype))
      return res.status(400).json({ message: "Only JPG, PNG or WebP allowed" });

    const dataUri = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
    const result = await cloudinary.uploader.upload(dataUri, {
      folder: "avatars",
      public_id: String(req.userId),
      overwrite: true,
      invalidate: true,
      transformation: [{ width: 400, height: 400, crop: "fill", gravity: "face" }],
    });

    const user = await User.findByIdAndUpdate(
      req.userId,
      { avatar: result.secure_url },
      { new: true }
    );
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Upload failed" });
  }
});
const ROLES = ["Admin", "Developer", "Viewer"];
const nameOf = (u) => u.name || (u.email || "").split("@")[0];
const canManage = (req) => req.role === "Owner" || req.role === "Admin";



app.post("/api/team/invite", auth, async (req, res) => {
  try {
    if (!canManage(req))
      return res.status(403).json({ message: "Only owners and admins can invite" });
    const email = String(req.body.email || "").trim().toLowerCase();
    const role = req.body.role;
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ message: "Enter a valid email" });
    if (!ROLES.includes(role)) return res.status(400).json({ message: "Invalid role" });
    const owner = await User.findById(req.userId);
    if (owner.email === email) return res.status(400).json({ message: "You are already the owner" });
    const target = await User.findOne({ email }).select("_id");
    if (target && (await Link.findOne(pairQ(req.userId, target._id))))
      return res.status(409).json({ message: "Already a member" });
    if (await Invite.findOne({ owner: req.userId, email, status: "Pending" }))
      return res.status(409).json({ message: "Invitation already sent" });
    const inviter = await User.findById(req.realId);
    await Invite.deleteMany({ owner: req.userId, email, status: "Declined" });
    await Invite.create({
      owner: req.userId, ownerName: nameOf(inviter), workspace: owner.workspace, email, role,
    });
    if (target) pushTo(target._id);
    pushTo(req.userId);
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});





// ---- invitee side (apna account, scope nahi) ----
app.get("/api/invites", auth, async (req, res) => {
  try {
    const me = await User.findById(req.userId).select("email");
    const rows = await Invite.find({ email: me.email, status: "Pending" }).sort({ createdAt: -1 });
    res.json(
      rows.map((i) => ({
        id: i._id.toString(), from: i.ownerName, workspace: i.workspace,
        role: i.role, ts: i.createdAt.getTime(),
      }))
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});



app.post("/api/invites/:id/decline", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid id" });
    const me = await User.findById(req.userId).select("email");
       const inv = await Invite.findOneAndUpdate(
      { _id: req.params.id, email: me.email, status: "Pending" }, { status: "Declined" }
    );
    if (inv) pushTo(inv.owner);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Live updates (SSE) ----------
const sseClients = new Map(); // userId -> Set(res)
const pushTo = (userId) => {
  const set = sseClients.get(String(userId));
  if (set) for (const r of set) r.write("data: refresh\n\n");
};
// Is user se jude sabhi logon (aur khud ko) refresh signal bhejo
const pushLinked = async (userId) => {
  pushTo(userId);
  const links = await Link.find({ $or: [{ a: userId }, { b: userId }] }).lean();
  for (const l of links) pushTo(String(l.a) === String(userId) ? l.b : l.a);
};
app.get("/api/events", (req, res) => {
  let id;
  try {
    id = jwt.verify(String(req.query.token || ""), process.env.JWT_SECRET).id;
  } catch {
    return res.status(401).end();
  }
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();
  res.write("retry: 3000\n\n");
  const key = String(id);
  if (!sseClients.has(key)) sseClients.set(key, new Set());
  sseClients.get(key).add(res);
  const ping = setInterval(() => res.write(": ping\n\n"), 25000);
  req.on("close", () => {
    clearInterval(ping);
    sseClients.get(key)?.delete(res);
  });
});
app.get("/api/team", auth, async (req, res) => {
  try {
    const me = req.userId;
const owner = await User.findById(me).select("name email avatar createdAt");
const links = await Link.find({ $or: [{ a: me }, { b: me }] }).lean();
const otherOf = (l) => (String(l.a) === String(me) ? l.b : l.a);
const users = await User.find({ _id: { $in: links.map(otherOf) } }).select("name email avatar").lean();
    const byId = new Map(users.map((u) => [String(u._id), u]));
const invites = await Invite.find({
  owner: me,
  status: { $in: ["Pending", "Declined"] },
}).sort({ createdAt: -1 });
    res.json({
      myRole: req.role,
      list: [
{
  id: owner._id.toString(), name: nameOf(owner), email: owner.email, avatar: owner.avatar || "",
  role: "Owner", status: "Active", kind: "owner", joinedAt: owner.createdAt.getTime(),
},
...links
  .filter((l) => byId.has(String(otherOf(l))))
  .map((l) => {
    const u = byId.get(String(otherOf(l)));
    return {
      id: String(u._id), name: nameOf(u), email: u.email, avatar: u.avatar || "",
      role: l.role, status: "Active", kind: "member", joinedAt: l.createdAt,
    };
  }),
...invites.map((i) => ({
  id: i._id.toString(), name: i.email.split("@")[0], email: i.email, avatar: "",
  role: i.role,
  status: i.status === "Declined" ? "Rejected" : "Invited",
  kind: "invite", joinedAt: null,
})),
      ],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/api/team/:id/role", auth, async (req, res) => {
  try {
    if (!canManage(req)) return res.status(403).json({ message: "Not allowed" });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid id" });
    const role = req.body.role;
    if (!ROLES.includes(role)) return res.status(400).json({ message: "Invalid role" });
    const inv = await Invite.findOneAndUpdate(
      { _id: req.params.id, owner: req.userId, status: "Pending" }, { role }
    );
    if (!inv) {
      const l = await Link.findOneAndUpdate(pairQ(req.userId, req.params.id), { role });
      if (!l) return res.status(404).json({ message: "Member not found" });
            pushTo(req.params.id);
      pushTo(req.userId);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/team/:id", auth, async (req, res) => {
  try {
    if (!canManage(req)) return res.status(403).json({ message: "Not allowed" });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid id" });
   const inv = await Invite.findOneAndDelete(
  { _id: req.params.id, owner: req.userId, status: { $in: ["Pending", "Declined"] } }
);
    if (!inv) {
      const l = await Link.findOneAndDelete(pairQ(req.userId, req.params.id));
      if (!l) return res.status(404).json({ message: "Member not found" });
    }
        // invite cancel hone par:
    const t = await User.findOne({ email: inv.email }).select("_id");
    if (t) pushTo(t._id);
    pushTo(req.userId);
    // member hatane par (Link delete ke baad):
    pushTo(req.params.id);
    pushTo(req.userId);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/invites/:id/accept", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid id" });
    const me = await User.findById(req.userId);
    const inv = await Invite.findOne({ _id: req.params.id, email: me.email, status: "Pending" });
    if (!inv) return res.status(404).json({ message: "Invitation not found" });
    if (String(inv.owner) === String(me._id))
      return res.status(400).json({ message: "This is your own workspace" });
    if (!(await Link.findOne(pairQ(inv.owner, me._id))))
      await Link.create({ a: inv.owner, b: me._id, role: inv.role });
    inv.status = "Accepted";
    await inv.save();
        pushTo(inv.owner);
    pushTo(me._id);
    res.json({ ok: true, owner: String(inv.owner) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// connected workspaces ki list (switcher ke liye)
app.get("/api/workspaces", auth, async (req, res) => {
  try {
    const me = req.userId;
    const links = await Link.find({ $or: [{ a: me }, { b: me }] }).lean();
    const otherOf = (l) => String(String(l.a) === String(me) ? l.b : l.a);
    const roleOf = new Map(links.map((l) => [otherOf(l), l.role]));
    const users = await User.find({ _id: { $in: [...roleOf.keys()] } })
      .select("name email workspace avatar").lean();
     res.json(
      users.map((u) => ({
        id: String(u._id), owner: nameOf(u), name: u.workspace,
        role: roleOf.get(String(u._id)), avatar: u.avatar || "",
      }))
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/membership/leave", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.body.id)) return res.status(400).json({ message: "Invalid id" });
    await Link.deleteOne(pairQ(req.userId, req.body.id));
        pushTo(req.body.id);
    pushTo(req.userId);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Current user + preferences (sync across browsers) ----------
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    const view = await resolveView(req.userId, req.headers["x-workspace"]);
    const out = publicUser(user);
    out.role = view.role;
    out.viewId = "";
     if (String(view.ownerId) !== String(user._id)) {
      const owner = await User.findById(view.ownerId).select("workspace name email");
      if (owner) {
        out.workspace = owner.workspace;
        out.viewName = nameOf(owner);
      }
      out.viewId = String(view.ownerId);
    }
    res.json({ user: out });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/auth/prefs", auth, async (req, res) => {
  try {
    const patch = {};
    if (["dark", "light"].includes(req.body.theme)) patch["prefs.theme"] = req.body.theme;
    if ("logsPausedAt" in req.body) {
      const v = req.body.logsPausedAt;
      patch["prefs.logsPausedAt"] = v === null ? null : Number(v) || null;
    }
        const mi = Number(req.body.monitorInterval);
    if ([15, 30, 60].includes(mi)) patch["prefs.monitorInterval"] = mi;
    if (typeof req.body.monitorPaused === "boolean")
      patch["prefs.monitorPaused"] = req.body.monitorPaused;
    if (!Object.keys(patch).length)
      return res.status(400).json({ message: "Nothing to update" });
    const user = await User.findByIdAndUpdate(req.userId, { $set: patch }, { new: true });
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Password change ----------
app.put("/api/auth/password", auth, async (req, res) => {
  try {
    const { password, confirm } = req.body;
    if (!password || password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (password !== confirm)
      return res.status(400).json({ message: "Passwords do not match" });
    const hashed = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(req.userId, { password: hashed });
    res.json({ message: "Password updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- DB + server start ----------
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = (req.body.email || "").toLowerCase();
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "Account not registered with this email" });

    const otp = String(crypto.randomInt(100000, 1000000)); // 6 digit
    user.resetOtpHash = crypto.createHash("sha256").update(otp).digest("hex");
    user.resetOtpExpires = Date.now() + 10 * 60 * 1000;
    user.resetOtpAttempts = 0;
    await user.save();

    await sendResetEmail(user.email, otp);
    res.json({ message: "We sent a 6-digit code to your email." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Could not send reset email" });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const email = (req.body.email || "").toLowerCase();
    const { otp } = req.body;

    const user = await User.findOne({ email });
    if (!user || !user.resetOtpHash || user.resetOtpExpires < Date.now())
      return res.status(400).json({ message: "Code expired. Please request a new one." });

    if (user.resetOtpAttempts >= 5)
      return res.status(429).json({ message: "Too many wrong attempts. Request a new code." });

    const hash = crypto.createHash("sha256").update(String(otp)).digest("hex");
    if (hash !== user.resetOtpHash) {
      user.resetOtpAttempts += 1;
      await user.save();
      return res.status(400).json({ message: "Incorrect code" });
    }

    user.resetOtpHash = undefined;
    user.resetOtpExpires = undefined;
    user.resetOtpAttempts = 0;
    await user.save();

    const resetToken = jwt.sign(
      { id: user._id, purpose: "reset" },
      process.env.JWT_SECRET + user.password,
      { expiresIn: "10m" }
    );
    res.json({ resetToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { resetToken, password, confirmPassword } = req.body;
    if (!resetToken)
      return res.status(400).json({ message: "Session expired. Please start again." });
    if (!password || password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (password !== confirmPassword)
      return res.status(400).json({ message: "Passwords do not match" });

    const decoded = jwt.decode(resetToken);
    if (!decoded?.id || !mongoose.isValidObjectId(decoded.id))
      return res.status(400).json({ message: "Session expired. Please start again." });

    const user = await User.findById(decoded.id);
    if (!user)
      return res.status(400).json({ message: "Session expired. Please start again." });

    try {
      const payload = jwt.verify(resetToken, process.env.JWT_SECRET + user.password);
      if (payload.purpose !== "reset") throw new Error("bad purpose");
    } catch {
      return res.status(400).json({ message: "Session expired. Please start again." });
    }

    user.password = await bcrypt.hash(password, 10);
    await user.save();

    res.json({ message: "Password updated. You can sign in now." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- API inventory ----------
const apiSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    name: { type: String, required: true, trim: true },
    baseUrl: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    favorite: { type: Boolean, default: false },
    endpoints: { type: Number, default: 0 },
    endpointList: [{ _id: false, method: String, path: String, summary: String }],
  },
  { timestamps: true }
);
const ApiEntry = mongoose.model("ApiEntry", apiSchema);
const apiOut = (a) => ({
  id: a._id.toString(),
  name: a.name,
  baseUrl: a.baseUrl,
  description: a.description,
  favorite: a.favorite,
  endpoints: a.endpoints,
  endpointList: (a.endpointList || []).map((e) => ({
    method: e.method,
    path: e.path,
    summary: e.summary,
  })),
  updatedAt: a.updatedAt.getTime(),
});
const cleanEndpoints = (list) =>
  (Array.isArray(list) ? list : [])
    .slice(0, 500)
    .map((e) => ({
      method: String(e?.method || "GET").toUpperCase().slice(0, 10),
      path: String(e?.path || "").slice(0, 300),
      summary: String(e?.summary || "").slice(0, 200),
    }))
    .filter((e) => e.path);
const cleanApi = (b) => {
  const name = String(b.name || "").trim();
  const baseUrl = String(b.baseUrl || "").trim();
  if (!name) return { error: "Service name is required" };
  try {
    if (!/^https?:$/.test(new URL(baseUrl).protocol)) throw new Error("bad");
  } catch {
    return { error: "Enter a valid http(s) base URL" };
  }
  return { name, baseUrl, description: String(b.description || "").trim() };
};

app.get("/api/apis", auth, async (req, res) => {
  try {
    const rows = await ApiEntry.find({ user: req.userId }).sort({ createdAt: -1 });
    res.json(rows.map(apiOut));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/apis", auth, async (req, res) => {
  try {
    const c = cleanApi(req.body);
    if (c.error) return res.status(400).json({ message: c.error });
     const endpointList = cleanEndpoints(req.body.endpointList);
    const row = await ApiEntry.create({
      ...c,
      user: req.userId,
      endpointList,
      endpoints: endpointList.length || Math.max(0, Number(req.body.endpoints) || 0),
    });
            lastRun.set(String(row._id), Date.now());
        runCheck(row, null, true).catch(() => {});
    res.status(201).json(apiOut(row));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/apis/:id", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    const c = cleanApi(req.body);
    if (c.error) return res.status(400).json({ message: c.error });
    const row = await ApiEntry.findOneAndUpdate(
      { _id: req.params.id, user: req.userId },
      c,
      { new: true }
    );
    if (!row) return res.status(404).json({ message: "API not found" });
    res.json(apiOut(row));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/api/apis/:id/favorite", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    const row = await ApiEntry.findOne({ _id: req.params.id, user: req.userId });
    if (!row) return res.status(404).json({ message: "API not found" });
    row.favorite = !row.favorite;
    await row.save();
    res.json(apiOut(row));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/apis/:id", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    await ApiEntry.deleteOne({ _id: req.params.id, user: req.userId });
    await CheckLog.deleteMany({ api: req.params.id, user: req.userId });
    await Incident.deleteMany({ api: req.params.id, user: req.userId });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Uptime monitoring ----------
const checkSchema = new mongoose.Schema({
  api: { type: mongoose.Schema.Types.ObjectId, ref: "ApiEntry", required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  state: { type: String, enum: ["up", "slow", "down"], required: true },
  status: { type: Number, default: 0 },
  latency: { type: Number, default: 0 },
  error: { type: String, default: "" },
  ts: { type: Number, default: () => Date.now() },
  createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 }, // 30 din baad auto delete
});
checkSchema.index({ api: 1, ts: -1 });
const CheckLog = mongoose.model("CheckLog", checkSchema);

const incidentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  api: { type: mongoose.Schema.Types.ObjectId, ref: "ApiEntry", required: true, index: true },
  apiName: String,
  kind: { type: String, enum: ["Down", "Degraded"], required: true },
  detail: { type: String, default: "" },
  startedAt: { type: Number, required: true },
  resolvedAt: { type: Number, default: null },
});
const Incident = mongoose.model("Incident", incidentSchema);

const SLOW_MS = Number(process.env.MONITOR_SLOW_MS) || 1500;

// SSRF se bachav: server ko private/internal addresses ping nahi karne dete
const isPrivateIp = (ip) => {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const v = ip.toLowerCase();
  return (
    v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe80") || v.startsWith("::ffff:127.") ||
    v.startsWith("::ffff:10.") || v.startsWith("::ffff:192.168.")
  );
};
const safeTarget = async (url) => {
  if (process.env.ALLOW_PRIVATE_MONITOR === "true") return true;
  const { hostname } = new URL(url);
  const addrs = await dns.lookup(hostname, { all: true });
  return addrs.every((a) => !isPrivateIp(a.address));
};

const pingOnce = async (url) => {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    if (!(await safeTarget(url)))
      return { state: "down", status: 0, latency: 0, error: "Private address blocked" };
    const r = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": "EasyAPI-Monitor/1.0" },
    });
    const latency = Date.now() - t0;
    try { await r.body?.cancel(); } catch {}
    const state = r.status >= 500 ? "down" : latency > SLOW_MS ? "slow" : "up";
    return { state, status: r.status, latency, error: "" };
  } catch (e) {
    return {
      state: "down",
      status: 0,
      latency: Date.now() - t0,
      error: e.name === "AbortError" ? "Timeout (10s)" : String(e.cause?.code || e.code || e.message).slice(0, 120),
    };
  } finally {
    clearTimeout(timer);
  }
};
const isPaused = async (userId) => {
  const u = await User.findById(userId).select("prefs.monitorPaused").lean();
  return !!u?.prefs?.monitorPaused;
};
const runCheck = async (api, open, force = false) => {
  if (!force && (await isPaused(api.user))) return null; // pause hai to check hi nahi
  console.log(`[monitor] checking ${api.name} at ${new Date().toLocaleTimeString()}`);
  let res = await pingOnce(api.baseUrl);
  if (res.state === "down") {
    await new Promise((r) => setTimeout(r, 2000)); // 1 retry, flapping se bachne ke liye
    res = await pingOnce(api.baseUrl);
  }
  await CheckLog.create({ api: api._id, user: api.user, ...res });

  const kind = res.state === "down" ? "Down" : res.state === "slow" ? "Degraded" : null;
  if (open && (!kind || open.kind !== kind)) {
    open.resolvedAt = Date.now();
    await open.save();
    open = null;
  }
  if (kind && !open) {
    await Incident.create({
      user: api.user,
      api: api._id,
      apiName: api.name,
      kind,
      startedAt: Date.now(),
      detail:
        kind === "Degraded"
          ? `Response time ${res.latency} ms (limit ${SLOW_MS} ms)`
          : res.error || `HTTP ${res.status}`,
    });
  }
  return res;
};

let monitorBusy = false;
const lastRun = new Map(); // apiId -> last check ka time
let lastMonitorTick = 0; // monitor loop ka last completion time
const runDueChecks = async () => {
  if (monitorBusy) return;
  monitorBusy = true;
  try {
    const users = await User.find({}).select("prefs").lean();
    const cfg = new Map(
      users.map((u) => [
        String(u._id),
        { every: u.prefs?.monitorInterval || 30, paused: !!u.prefs?.monitorPaused },
      ])
    );
    const apis = await ApiEntry.find({});
    const now = Date.now();
    const due = apis.filter((a) => {
      const c = cfg.get(String(a.user));
      if (!c || c.paused) return false;
      return now - (lastRun.get(String(a._id)) || 0) >= c.every * 1000 - 500;
    });
    if (!due.length) return;
    const open = await Incident.find({ resolvedAt: null });
    const byApi = new Map(open.map((i) => [String(i.api), i]));
    for (let i = 0; i < due.length; i += 10) {
      await Promise.allSettled(
        due.slice(i, i + 10).map((a) => {
          lastRun.set(String(a._id), Date.now());
          return runCheck(a, byApi.get(String(a._id)) || null);
        })
      );
    }
  } catch (err) {
    console.error("Monitor error:", err.message);
  } finally {
     lastMonitorTick = Date.now(); 
    monitorBusy = false;
  }
};
const startMonitor = () => {
  lastMonitorTick = Date.now(); 
  runDueChecks();
  setInterval(runDueChecks, 5000); // har 5 sec dekhta hai kaunsi API ka time ho gaya
  console.log("Monitor running (per-user interval)");
};

const lastManual = new Map();
app.post("/api/monitor/check/:id", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    const api = await ApiEntry.findOne({ _id: req.params.id, user: req.userId });
    if (!api) return res.status(404).json({ message: "API not found" });
    const key = String(api._id);
    if (Date.now() - (lastManual.get(key) || 0) < 5000)
      return res.status(429).json({ message: "Wait a few seconds" });
    lastManual.set(key, Date.now());
    const open = await Incident.findOne({ api: api._id, resolvedAt: null });
        await runCheck(api, open, true);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/monitor", auth, async (req, res) => {
  try {
    const me = await User.findById(req.userId).select("prefs").lean();
    const apis = await ApiEntry.find({ user: req.userId }).sort({ createdAt: 1 });
    const since = Date.now() - 24 * 3600e3;

    const counts = await CheckLog.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(req.userId), ts: { $gte: since } } },
      { $group: { _id: { api: "$api", down: { $eq: ["$state", "down"] } }, n: { $sum: 1 } } },
    ]);
    const stats = new Map();
    for (const c of counts) {
      const k = String(c._id.api);
      const s = stats.get(k) || { total: 0, down: 0 };
      s.total += c.n;
      if (c._id.down) s.down += c.n;
      stats.set(k, s);
    }

    const out = await Promise.all(
      apis.map(async (a) => {
        const recent = (
          await CheckLog.find({ api: a._id }).sort({ ts: -1 }).limit(24).lean()
        ).reverse();
        const last = recent[recent.length - 1];
        const s = stats.get(String(a._id)) || { total: 0, down: 0 };
        return {
          id: a._id.toString(),
          name: a.name,
          baseUrl: a.baseUrl,
          status: !last
            ? "Pending"
            : last.state === "up"
              ? "Operational"
              : last.state === "slow"
                ? "Degraded"
                : "Down",
          latency: last && last.state !== "down" ? last.latency : 0,
          statusCode: last ? last.status : 0,
          error: last ? last.error : "",
          lastCheckedAt: last ? last.ts : null,
          uptime: s.total ? Math.round(((s.total - s.down) / s.total) * 1000) / 10 : null,
          checks: s.total,
          bars: recent.map((c) => ({ state: c.state, ts: c.ts, latency: c.latency })),
        };
      })
    );

    const incidents = await Incident.find({ user: req.userId }).sort({ startedAt: -1 }).limit(15).lean();
    res.json({
      intervalSec: me?.prefs?.monitorInterval || 30,
      paused: !!me?.prefs?.monitorPaused,
      apis: out,
      incidents: incidents.map((i) => ({
        id: i._id.toString(),
        apiName: i.apiName,
        kind: i.kind,
        detail: i.detail,
        startedAt: i.startedAt,
        resolvedAt: i.resolvedAt,
      })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
app.get("/api/monitor/:id", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    const api = await ApiEntry.findOne({ _id: req.params.id, user: req.userId });
    if (!api) return res.status(404).json({ message: "API not found" });

    const since = Date.now() - 24 * 3600e3;
    const list = await CheckLog.find({ api: api._id, ts: { $gte: since } })
      .select("state status latency ts")
      .sort({ ts: 1 })
      .lean();

    const alive = list.filter((c) => c.state !== "down");
    const lat = alive.map((c) => c.latency).sort((a, b) => a - b);
    const avg = lat.length ? Math.round(lat.reduce((s, n) => s + n, 0) / lat.length) : 0;
    const p95 = lat.length ? lat[Math.max(0, Math.ceil(lat.length * 0.95) - 1)] : 0;

    const step = Math.max(1, Math.ceil(list.length / 120)); // chart ke liye max ~120 points
    const points = list
      .filter((_, i) => i % step === 0 || i === list.length - 1)
      .map((c) => ({ ts: c.ts, latency: c.latency, state: c.state }));

    res.json({
      checks: list.length,
      uptime: list.length ? Math.round((alive.length / list.length) * 1000) / 10 : null,
      avg,
      p95,
      points,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Public status ----------
const platformDaySchema = new mongoose.Schema({
  day: { type: String, unique: true },            // "2026-11-02" (UTC)
  up: { type: Number, default: 0 },
  slow: { type: Number, default: 0 },
  down: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 120 },
});
const PlatformDay = mongoose.model("PlatformDay", platformDaySchema);

const dayKey = (ms = Date.now()) => new Date(ms).toISOString().slice(0, 10);

const computeStatus = async () => {
  // DB check andar hi hai, user ko alag se nahi dikhana
  let api = "outage";
  try {
    const t0 = Date.now();
    await mongoose.connection.db.admin().ping();
    api = Date.now() - t0 > 500 ? "degraded" : "operational";
  } catch {}

  const age = Date.now() - lastMonitorTick;
  const monitoring = age < 60000 ? "operational" : age < 180000 ? "degraded" : "outage";

  return [
    { name: "API platform", status: api },
    { name: "Monitoring & alerts", status: monitoring },
  ];
};

// har 1 min mein ek sample, aaj ke din ke counter mein
const heartbeat = async () => {
  try {
    const s = await computeStatus();
    const worst = s.some((x) => x.status === "outage")
      ? "down"
      : s.some((x) => x.status === "degraded")
        ? "slow"
        : "up";
    await PlatformDay.updateOne({ day: dayKey() }, { $inc: { [worst]: 1 } }, { upsert: true });
  } catch (e) {
    console.error("heartbeat:", e.message);
  }
};

let statusCache = { at: 0, data: null };
app.get("/api/public-status", async (req, res) => {
  try {
    if (statusCache.data && Date.now() - statusCache.at < 15000) return res.json(statusCache.data);

    const services = await computeStatus();
    const rows = await PlatformDay.find({ day: { $gte: dayKey(Date.now() - 89 * 864e5) } }).lean();
    const byDay = new Map(rows.map((r) => [r.day, r]));

    let good = 0, total = 0;
    const days = [];
    for (let i = 89; i >= 0; i--) {
      const day = dayKey(Date.now() - i * 864e5);
      const r = byDay.get(day);
      const t = r ? r.up + r.slow + r.down : 0;
      let status = "none"; // us din ka data nahi
      if (t) {
        total += t;
        good += r.up + r.slow;
        status = r.down / t > 0.01 ? "down" : (r.slow + r.down) / t > 0.05 ? "slow" : "up";
      }
      days.push({ date: day, status });
    }

    const data = {
      services,
      uptime90: total ? Math.round((good / total) * 10000) / 100 : null,
      days,
      checkedAt: Date.now(),
    };
    statusCache = { at: Date.now(), data };
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------- Request logs (tester history for dashboard) ----------
app.get("/api/requests", auth, async (req, res) => {
  try {
    const rows = await RequestLog.find({ user: req.userId }).sort({ ts: -1 }).limit(500);
    res.json(rows.map(logOut));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/requests", auth, async (req, res) => {
  try {
    const { method, path, status, duration, api } = req.body;
    const row = await RequestLog.create({
      user: req.userId,
      method: String(method || "GET").toUpperCase(),
      path: String(path || ""),
      status: Number(status) || 0,
      duration: Number(duration) || 0,
      api: api || "Request tester",
    });
    res.status(201).json(logOut(row));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/requests/:id", auth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({ message: "Invalid id" });
    await RequestLog.deleteOne({ _id: req.params.id, user: req.userId });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/requests", auth, async (req, res) => {
  try {
    await RequestLog.deleteMany({ user: req.userId });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    startMonitor();
    heartbeat();
    setInterval(heartbeat, 60 * 1000);
    app.listen(process.env.PORT || 5000, () =>
      console.log(`Server on port ${process.env.PORT || 5000}`)
    );
  })
  .catch((err) => console.error("Mongo error:", err.message));