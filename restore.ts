import { prisma } from "../src/lib/prisma";
import fs from "node:fs";
import path from "node:path";
import bcrypt from "bcryptjs";

async function restoreDatabase(backupPath?: string) {
  const backupDir = path.join(process.cwd(), "prisma", "backup");

  if (!fs.existsSync(backupDir)) {
    throw new Error("Backup directory does not exist");
  }

  // If no specific backup path is provided, use the latest backup
  let targetBackupPath = backupPath;
  if (!targetBackupPath) {
    const backups = fs.readdirSync(backupDir)
      .filter(dir => dir.startsWith("backup-"))
      .sort()
      .reverse();

    if (backups.length === 0) {
      throw new Error("No backups found");
    }

    targetBackupPath = path.join(backupDir, backups[0]);
  }

  if (!fs.existsSync(targetBackupPath)) {
    throw new Error(`Backup path does not exist: ${targetBackupPath}`);
  }

  try {
    console.log(`Starting database restore from: ${targetBackupPath}`);

    // Read metadata
    const metadataPath = path.join(targetBackupPath, "metadata.json");
    if (fs.existsSync(metadataPath)) {
      const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf-8"));
      console.log("Backup metadata:", metadata);
    }

    // Restore Users
    const usersPath = path.join(targetBackupPath, "users.json");
    if (fs.existsSync(usersPath)) {
      const users = JSON.parse(fs.readFileSync(usersPath, "utf-8"));

      for (const user of users) {
        // Set default password if not present
        const defaultPassword = await bcrypt.hash("123456789", 10);
        const userData = {
          ...user,
          password: user.password || defaultPassword
        };

        await prisma.user.upsert({
          where: { id: user.id },
          update: userData,
          create: userData,
        });
      }
      console.log(`Restored ${users.length} users`);
    }

    // Restore Contratos
    const contratosPath = path.join(targetBackupPath, "contratos.json");
    if (fs.existsSync(contratosPath)) {
      const contratos = JSON.parse(fs.readFileSync(contratosPath, "utf-8"));

      for (const contrato of contratos) {
        await prisma.contrato.upsert({
          where: { id: contrato.id },
          update: contrato,
          create: contrato,
        });
      }
      console.log(`Restored ${contratos.length} contratos`);
    }

    // Restore Chats
    const chatsPath = path.join(targetBackupPath, "chats.json");
    if (fs.existsSync(chatsPath)) {
      const chats = JSON.parse(fs.readFileSync(chatsPath, "utf-8"));

      for (const chat of chats) {
        await prisma.chat.upsert({
          where: { id: chat.id },
          update: chat,
          create: chat,
        });
      }
      console.log(`Restored ${chats.length} chats`);
    }

    // Restore Messages
    const messagesPath = path.join(targetBackupPath, "messages.json");
    if (fs.existsSync(messagesPath)) {
      const messages = JSON.parse(fs.readFileSync(messagesPath, "utf-8"));

      for (const message of messages) {
        await prisma.message.upsert({
          where: { id: message.id },
          update: message,
          create: message,
        });
      }
      console.log(`Restored ${messages.length} messages`);
    }

    console.log("Database restore completed successfully!");

  } catch (error) {
    console.error("Restore failed:", error);
    throw error;
  }
}

// Get backup path from command line argument
const backupPath = process.argv[2];

restoreDatabase(backupPath)
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 