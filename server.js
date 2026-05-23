const express = require("express");
const { runAgent } = require("./agent");

const app = express();
app.use(express.json());

// ✅ Health check (useful for Railway)
app.get("/", (req, res) => {
  res.send("✅ OneTrust Agent is running");
});

// ✅ Main endpoint
app.post("/check", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        error: "Missing url in request body"
      });
    }

    console.log("🔍 Checking:", url);

    const result = await runAgent(url);

    res.json(result);

  } catch (err) {
    console.error("❌ Error:", err);

    res.status(500).json({
      error: "Failed to process request"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});