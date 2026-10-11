// Tiny demo "model" for local testing: node backend/mock-model.js  ->  http://localhost:5000
require("express")().use(require("express").json()).post("/", (req, res) => {
  const t = String(req.body.input || "").toLowerCase();
  const score = ["good","great","love","amazing"].filter(w=>t.includes(w)).length - ["bad","hate","awful"].filter(w=>t.includes(w)).length;
  res.json({ label: score >= 0 ? "positive" : "negative", score });
}).listen(5000, () => console.log("Mock model on :5000"));
