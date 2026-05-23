import express from "express";
import { runCheck } from "./agent.js";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("✅ OT checker running");
});

app.post("/check", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "Missing URL" });
    }

    const result = await runCheck(url);

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something failed" });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Listening on ${PORT}`);
});