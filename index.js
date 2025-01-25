// index.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(
  cors({
    origin: ["http://localhost:5000", "https://your-client-domain.vercel.app"],
    credentials: true,
  })
);
app.use(express.json());

// MongoDB Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  title: { type: String, required: true },
  completed: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Task = mongoose.model("Task", taskSchema);

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    // useNewUrlParser: true,
    // useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Middleware
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

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, email, password: hashedPassword }).save();
    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

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
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/tasks", authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.userId }).sort({
      created_at: -1,
    });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ message: "Error fetching tasks" });
  }
});

app.post("/api/tasks", authenticateToken, async (req, res) => {
  try {
    const taskCount = await Task.countDocuments({ userId: req.user.userId });
    if (taskCount >= 10) {
      return res.status(400).json({ message: "Task limit reached (max 10)" });
    }

    const task = await new Task({
      userId: req.user.userId,
      title: req.body.title,
    }).save();

    res.status(201).json({ id: task._id, message: "Task created" });
  } catch (error) {
    res.status(500).json({ message: "Error creating task" });
  }
});

app.patch("/api/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { completed: req.body.completed },
      { new: true }
    );

    if (!task) return res.status(404).json({ message: "Task not found" });
    res.json({ message: "Task updated" });
  } catch (error) {
    res.status(500).json({ message: "Error updating task" });
  }
});

app.delete("/api/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId,
    });

    if (!task) return res.status(404).json({ message: "Task not found" });
    res.json({ message: "Task deleted" });
  } catch (error) {
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
