import { prisma } from "../src/lib/prisma";
import fs from "node:fs";
import path from "node:path";

async function backupDatabase() {
  const backupDir = path.join(process.cwd(), "prisma", "backup");

  // Create backup directory if it doesn't exist
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupDir, `backup-${timestamp}`);

  // Create timestamped backup directory
  fs.mkdirSync(backupPath, { recursive: true });

  try {
    console.log("Starting database backup...");

    // Backup Users
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "asc" },
    });

    fs.writeFileSync(
      path.join(backupPath, "users.json"),
      JSON.stringify(users, null, 2)
    );
    console.log(`Backed up ${users.length} users`);

    // Backup Contratos
    const contratos = await prisma.contrato.findMany({
      orderBy: { createdAt: "asc" },
    });

    fs.writeFileSync(
      path.join(backupPath, "contratos.json"),
      JSON.stringify(contratos, null, 2)
    );
    console.log(`Backed up ${contratos.length} contratos`);

    // Backup Chats
    const chats = await prisma.chat.findMany({
      orderBy: { createdAt: "asc" },
    });

    fs.writeFileSync(
      path.join(backupPath, "chats.json"),
      JSON.stringify(chats, null, 2)
    );
    console.log(`Backed up ${chats.length} chats`);

    // Backup Messages
    const messages = await prisma.message.findMany({
      orderBy: { createdAt: "asc" },
    });

    fs.writeFileSync(
      path.join(backupPath, "messages.json"),
      JSON.stringify(messages, null, 2)
    );
    console.log(`Backed up ${messages.length} messages`);

    // Create backup metadata
    const metadata = {
      timestamp: new Date().toISOString(),
      totalRecords: {
        users: users.length,
        contratos: contratos.length,
        chats: chats.length,
        messages: messages.length,
      },
      schemaVersion: "1.0",
    };

    fs.writeFileSync(
      path.join(backupPath, "metadata.json"),
      JSON.stringify(metadata, null, 2)
    );

    console.log(`Backup completed successfully at: ${backupPath}`);
    return backupPath;

  } catch (error) {
    console.error("Backup failed:", error);
    throw error;
  }
}

backupDatabase()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 