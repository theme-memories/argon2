import { Hono, Context } from "hono";
import * as argon2 from "argon2";
import { MongoClient } from "mongodb";
import nodeCrypto from "node:crypto";

type responseBody = {
  success: boolean;
  errcode: string | null;
};

const app = new Hono();
const mongoClient = new MongoClient(
  process.env.MONGODB_URI || "mongodb://localhost:27017",
);
const dbName = "theme_memories";

async function hmacCalculate(key: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(message);
  const cryptoKey = await nodeCrypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await nodeCrypto.subtle.sign(
    "HMAC",
    cryptoKey,
    messageData,
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function signedJson(
  c: Context,
  body: responseBody,
  status: number = 200,
) {
  const hmacV2C = process.env.HMAC_SECRET_V2C;

  if (!hmacV2C) {
    console.error("HMAC secret for V2C is not set in environment variables.");
    return c.json({ success: false, errcode: "CONFIG_ERROR" }, 500);
  }

  const responseData = JSON.stringify(body);
  const responseHmac = await hmacCalculate(hmacV2C, responseData);
  c.header("X-Amia-HMAC", responseHmac);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return c.json(body, status as any);
}

app.post("/headrest8021", async (c) => {
  try {
    const requestRaw = await c.req.text();
    const requestHmac = c.req.header("X-Amia-HMAC");
    const requestTimestamp = c.req.header("X-Amia-Timestamp");
    const hmacC2V = process.env.HMAC_SECRET_C2V;

    if (!hmacC2V) {
      console.error("HMAC secret for C2V is not set in environment variables.");
      return await signedJson(
        c,
        { success: false, errcode: "CONFIG_ERROR" },
        500,
      );
    }

    const calculatedHmac = await hmacCalculate(hmacC2V, requestRaw);
    const calculatedHmacBuf = Buffer.from(calculatedHmac, "base64");
    const requestHmacBuf = Buffer.from(requestHmac || "", "base64");

    if (
      calculatedHmacBuf.length !== requestHmacBuf.length ||
      !nodeCrypto.timingSafeEqual(calculatedHmacBuf, requestHmacBuf)
    ) {
      return await signedJson(
        c,
        { success: false, errcode: "INVALID_HMAC" },
        401,
      );
    }

    const { slug, answer, timestamp } = await c.req.json();

    if (
      typeof slug !== "string" ||
      typeof answer !== "string" ||
      typeof timestamp !== "string"
    ) {
      return await signedJson(
        c,
        { success: false, errcode: "INVALID_INPUT" },
        400,
      );
    }

    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
      return await signedJson(
        c,
        { success: false, errcode: "INVALID_SLUG" },
        400,
      );
    }

    if (/[^a-zA-Z0-9!@#$%^&*]/.test(answer)) {
      return await signedJson(
        c,
        { success: false, errcode: "INVALID_ANSWER" },
        400,
      );
    }

    if (requestTimestamp !== timestamp) {
      return await signedJson(
        c,
        { success: false, errcode: "TIMESTAMP_MISMATCH" },
        400,
      );
    }

    if (
      isNaN(Number(timestamp)) ||
      Math.abs(Date.now() - Number(timestamp)) > 10 * 1000
    ) {
      return await signedJson(
        c,
        { success: false, errcode: "TIMESTAMP_EXPIRED" },
        400,
      );
    }

    const db = mongoClient.db(dbName);
    const collection = db.collection("hashpwd");
    const user = await collection.findOne({ slug });

    if (!user) {
      return await signedJson(c, { success: false, errcode: "NOT_FOUND" }, 404);
    }

    const isValid = await argon2.verify(user.passwordHash, answer);

    if (isValid) {
      return await signedJson(c, { success: true, errcode: null });
    } else {
      return await signedJson(
        c,
        { success: false, errcode: "WRONG_ANSWER" },
        401,
      );
    }
  } catch (error) {
    console.error("Verification error:", error);
    return await signedJson(
      c,
      { success: false, errcode: "INTERNAL_ERROR" },
      500,
    );
  }
});

export default app;
