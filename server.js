const express = require("express");
const admin = require("firebase-admin");

const PORT = process.env.PORT || 3000;
const COLLECTIONS = (process.env.NOTIFICATION_COLLECTIONS || "notifications")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const DELETE_EXISTING_ON_STARTUP =
  String(process.env.DELETE_EXISTING_ON_STARTUP || "false").toLowerCase() === "true";

function getFirebaseCredentials() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      "Missing FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, or FIREBASE_PRIVATE_KEY environment variables."
    );
  }

  // Railway variables often contain literal \n instead of real line breaks.
  privateKey = privateKey.replace(/\\n/g, "\n");

  return { projectId, clientEmail, privateKey };
}

const credentials = getFirebaseCredentials();

admin.initializeApp({
  credential: admin.credential.cert(credentials)
});

const db = admin.firestore();

const app = express();
app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "Durosak Notification Watcher",
    status: "running",
    collections: COLLECTIONS
  });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    uptimeSeconds: Math.floor(process.uptime()),
    collections: COLLECTIONS
  });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Watching collections: ${COLLECTIONS.join(", ")}`);
});

const unsubscribeFunctions = [];

function watchCollection(collectionName) {
  console.log(`[WATCH] Starting listener for: ${collectionName}`);

  let firstSnapshot = true;

  const unsubscribe = db.collection(collectionName).onSnapshot(
    async (snapshot) => {
      // Firestore sends the current contents on the first snapshot.
      // We normally ignore those so a server restart does not delete
      // notifications that existed before the watcher started.
      if (firstSnapshot) {
        firstSnapshot = false;

        console.log(
          `[WATCH] ${collectionName}: initial snapshot received (${snapshot.size} docs).`
        );

        if (DELETE_EXISTING_ON_STARTUP && snapshot.size > 0) {
          for (const doc of snapshot.docs) {
            await deleteNotification(collectionName, doc);
          }
        }

        return;
      }

      const added = snapshot.docChanges().filter(change => change.type === "added");

      for (const change of added) {
        await deleteNotification(collectionName, change.doc);
      }
    },
    (error) => {
      console.error(`[WATCH ERROR] ${collectionName}:`, error);
    }
  );

  unsubscribeFunctions.push(unsubscribe);
}

async function deleteNotification(collectionName, doc) {
  try {
    const data = doc.data();

    await doc.ref.delete();

    console.log(
      JSON.stringify({
        event: "notification_deleted",
        collection: collectionName,
        documentId: doc.id,
        timestamp: new Date().toISOString(),
        fields: Object.keys(data || {})
      })
    );
  } catch (error) {
    console.error(
      `[DELETE ERROR] ${collectionName}/${doc.id}:`,
      error
    );
  }
}

for (const collectionName of COLLECTIONS) {
  watchCollection(collectionName);
}

function shutdown(signal) {
  console.log(`[SHUTDOWN] Received ${signal}. Closing listeners...`);

  for (const unsubscribe of unsubscribeFunctions) {
    try {
      unsubscribe();
    } catch (_) {}
  }

  setTimeout(() => process.exit(0), 500);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
