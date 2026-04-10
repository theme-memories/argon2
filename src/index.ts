import { Hono } from "hono";
import * as argon2 from "argon2";
import { MongoClient } from "mongodb";

const app = new Hono();
const mongoClient = new MongoClient(
  process.env.MONGODB_URI || "mongodb://localhost:27017",
);
const dbName = "theme_memories"; // Replace with actual DB name

app.post("/headrest8021", async (c) => {
  try {
    const { slug, answer } = await c.req.json();

    if (!slug || !answer) {
      return c.json({ success: false, errcode: "MISSING_PARAMS" }, 400);
    }

    const db = mongoClient.db(dbName);
    const collection = db.collection("hashpwd"); // Adjust collection name as needed
    const user = await collection.findOne({ slug });

    if (!user || !user.passwordHash) {
      return c.json({ success: false, errcode: "NOT_FOUND" }, 404);
    }

    const isValid = await argon2.verify(user.passwordHash, answer);

    if (isValid) {
      return c.json({ success: true, errcode: null });
    } else {
      return c.json({ success: false, errcode: "WRONG_ANSWER" }, 401);
    }
  } catch (error) {
    console.error("Verification error:", error);
    return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
  }
});

export default app;
