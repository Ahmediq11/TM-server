// index.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);

// Rate limiting per user
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5, // start blocking after 5 requests
  message: "Too many accounts created, please try again after an hour",
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.userId || req.ip, // Rate limit by user ID if authenticated, otherwise by IP
});

app.use("/api/register", createAccountLimiter);
app.use("/api", apiLimiter);

app.use(
  cors({
    origin: ["https://tm-client.vercel.app", "http://localhost:3000"],
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// Performance optimized schemas
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, index: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
  },
  {
    timestamps: true,
    versionKey: "__v",
  }
);

const taskSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    title: { type: String, required: true },
    completed: { type: Boolean, default: false, index: true },
    created_at: { type: Date, default: Date.now, index: true },
  },
  {
    timestamps: true,
    versionKey: "__v",
  }
);

// Add compound index for common queries
taskSchema.index({ userId: 1, completed: 1, created_at: -1 });

const User = mongoose.model("User", userSchema);
const Task = mongoose.model("Task", taskSchema);

// Configure MongoDB with performance optimizations
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    connectTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    maxPoolSize: 50,
    minPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ message: "Authentication required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

const validateRegistration = [
  body("username").trim().isLength({ min: 3 }).escape(),
  body("email").isEmail().normalizeEmail(),
  body("password").isLength({ min: 6 }),
];

const validateTask = [body("title").trim().isLength({ min: 1 }).escape()];

// Cache middleware
const cacheControl = (maxAge) => (req, res, next) => {
  res.set("Cache-Control", `private, max-age=${maxAge}`);
  next();
};

app.get("/", (req, res) => {
  res.json({ message: "Server is running" });
});

app.post("/api/register", validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] })
      .select("_id")
      .lean();

    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, email, password: hashedPassword }).save();
    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username }).select("+password").lean();

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/tasks", authenticateToken, cacheControl(10), async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.userId })
      .select("title completed created_at")
      .sort({ created_at: -1 })
      .lean();

    // Generate ETag for caching
    const etag = crypto
      .createHash("md5")
      .update(JSON.stringify(tasks))
      .digest("hex");

    // Return 304 if client's cache is valid
    if (req.headers["if-none-match"] === etag) {
      return res.status(304).send();
    }

    res.set("ETag", etag);
    res.json(tasks);
  } catch (error) {
    console.error("Fetch tasks error:", error);
    res.status(500).json({ message: "Error fetching tasks" });
  }
});

app.post("/api/tasks", [authenticateToken, validateTask], async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const taskCount = await Task.countDocuments({
      userId: req.user.userId,
    }).session(session);
    if (taskCount >= 10) {
      return res.status(400).json({ message: "Task limit reached (max 10)" });
    }

    const task = await new Task({
      userId: req.user.userId,
      title: req.body.title,
    }).save({ session });

    await session.commitTransaction();
    res.status(201).json({ id: task._id, message: "Task created" });
  } catch (error) {
    await session.abortTransaction();
    console.error("Create task error:", error);
    res.status(500).json({ message: "Error creating task" });
  } finally {
    session.endSession();
  }
});

app.patch("/api/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { completed: req.body.completed },
      { new: true, lean: true }
    ).select("completed");

    if (!task) return res.status(404).json({ message: "Task not found" });
    res.json({ message: "Task updated", task });
  } catch (error) {
    console.error("Update task error:", error);
    res.status(500).json({ message: "Error updating task" });
  }
});

app.delete("/api/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId,
    }).lean();

    if (!task) return res.status(404).json({ message: "Task not found" });
    res.json({ message: "Task deleted" });
  } catch (error) {
    console.error("Delete task error:", error);
    res.status(500).json({ message: "Error deleting task" });
  }
});

const port = process.env.PORT || 5000;
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

module.exports = app;
