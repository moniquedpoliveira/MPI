import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";
import fs from "node:fs";
import path from "node:path";

const prisma = new PrismaClient();

// Checklist Administrativo
const checklistAdministrativo = [
  "Acompanhar o cumprimento dos prazos contratuais",
  "Verificar a regularidade da documentação contratual",
  "Controlar a conformidade dos pagamentos",
  "Registrar e acompanhar a execução de termos aditivos",
  "Analisar a regularidade das garantias contratuais",
  "Controlar o cumprimento de obrigações trabalhistas e previdenciárias",
  "Fiscalizar o cumprimento de normas de transparência",
  "Verificar a adequação dos termos de encerramento contratual",
];

// Checklist Técnico
const checklistTecnico = [
  "Realizar o recebimento provisório dos itens",
  "Inspecionar fisicamente os bens",
  "Verificar certificados e garantias",
  "Realizar testes de funcionamento (quando aplicável)",
  "Verificar o prazo de validade (para produtos perecíveis ou de consumo)",
  "Acompanhar o transporte e as condições de armazenamento",
  "Aceitar ou rejeitar os bens",
  "Registrar os itens no controle de estoque (quando aplicável)",
  "Monitorar o pós-entrega",
];

const mockUsers = [
  {
    email: "admin@admin.com",
    password: "123456",
    name: "Administrador do Sistema",
    role: "ADMINISTRADOR" as const,
  },
  {
    email: "gestor@gestor.com",
    password: "123456",
    name: "Gestor do Contrato",
    role: "GESTOR_CONTRATO" as const,
  },
  {
    email: "fiscal.adm@fiscal.com",
    password: "123456",
    name: "Fiscal Administrativo",
    role: "FISCAL_ADMINISTRATIVO" as const,
  },
  {
    email: "fiscal.tec@fiscal.com",
    password: "123456",
    name: "Fiscal Técnico",
    role: "FISCAL_TECNICO" as const,
  },
  {
    email: "ordenador@ordenador.com",
    password: "123456",
    name: "Ordenador de Despesas",
    role: "ORDENADOR_DESPESAS" as const,
  },
];

async function restoreFromBackup() {
  const backupDir = path.join(process.cwd(), "prisma", "backup");
  if (!fs.existsSync(backupDir)) {
    console.log("No backup directory found, skipping restore");
    return;
  }
  const backups = fs
    .readdirSync(backupDir)
    .filter((dir) => dir.startsWith("backup-"))
    .sort()
    .reverse();
  if (backups.length === 0) {
    console.log("No backups found, skipping restore");
    return;
  }
  const latestBackup = path.join(backupDir, backups[0]);
  console.log(`Restoring from latest backup: ${latestBackup}`);

  // Restore Users
  const usersPath = path.join(latestBackup, "users.json");
  if (fs.existsSync(usersPath)) {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf-8"));
    for (const user of users) {
      const defaultPassword = await bcrypt.hash("123456789", 10);
      const userData = {
        ...user,
        password: user.password || defaultPassword,
      };
      await prisma.user.upsert({
        where: { id: user.id },
        update: userData,
        create: userData,
      });
    }
    console.log(`Restored ${users.length} users from backup`);
  }
  // Restore Contratos
  const contratosPath = path.join(latestBackup, "contratos.json");
  if (fs.existsSync(contratosPath)) {
    const contratos = JSON.parse(fs.readFileSync(contratosPath, "utf-8"));
    for (const contrato of contratos) {
      await prisma.contrato.upsert({
        where: { id: contrato.id },
        update: contrato,
        create: contrato,
      });
    }
    console.log(`Restored ${contratos.length} contratos from backup`);
  }
  // Restore Chats
  const chatsPath = path.join(latestBackup, "chats.json");
  if (fs.existsSync(chatsPath)) {
    const chats = JSON.parse(fs.readFileSync(chatsPath, "utf-8"));
    for (const chat of chats) {
      await prisma.chat.upsert({
        where: { id: chat.id },
        update: chat,
        create: chat,
      });
    }
    console.log(`Restored ${chats.length} chats from backup`);
  }
  // Restore Messages
  const messagesPath = path.join(latestBackup, "messages.json");
  if (fs.existsSync(messagesPath)) {
    const messages = JSON.parse(fs.readFileSync(messagesPath, "utf-8"));
    for (const message of messages) {
      await prisma.message.upsert({
        where: { id: message.id },
        update: message,
        create: message,
      });
    }
    console.log(`Restored ${messages.length} messages from backup`);
  }
}

async function seedChecklists() {
  // Administrativa
  for (const text of checklistAdministrativo) {
    const existing = await prisma.checklist.findFirst({
      where: { text, type: "ADMINISTRATIVA" },
    });
    if (!existing) {
      await prisma.checklist.create({
        data: { text, type: "ADMINISTRATIVA" },
      });
    }
  }
  // Técnica
  for (const text of checklistTecnico) {
    const existing = await prisma.checklist.findFirst({
      where: { text, type: "TECNICA" },
    });
    if (!existing) {
      await prisma.checklist.create({
        data: { text, type: "TECNICA" },
      });
    }
  }
  console.log(
    `✅ Created/ensured ${checklistAdministrativo.length} administrative checklist items`
  );
  console.log(
    `✅ Created/ensured ${checklistTecnico.length} technical checklist items`
  );
}

async function ensureSuperAdmin() {
  const email = process.env.SUPER_ADMIN_EMAIL;
  const password = process.env.SUPER_ADMIN_PASSWORD;
  if (!email || !password) {
    throw new Error(
      "SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD must be set in .env"
    );
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const superAdmin = await prisma.user.upsert({
    where: { email },
    update: {
      password: hashedPassword,
      isActive: true,
      name: "Super Administrador",
      role: "ADMINISTRADOR",
    },
    create: {
      email,
      password: hashedPassword,
      isActive: true,
      name: "Super Administrador",
      role: "ADMINISTRADOR",
    },
  });
  console.log("Super admin user ensured:", superAdmin.email);
}

async function ensureMockUsers() {
  for (const userData of mockUsers) {
    const hashedUserPassword = await bcrypt.hash(userData.password, 10);
    const user = await prisma.user.upsert({
      where: { email: userData.email },
      update: {
        password: hashedUserPassword,
        isActive: true,
        name: userData.name,
        role: userData.role,
      },
      create: {
        email: userData.email,
        password: hashedUserPassword,
        isActive: true,
        name: userData.name,
        role: userData.role,
      },
    });
    console.log(`Ensured ${userData.role} user:`, user.email);
  }
  console.log("All mock users ensured successfully!");
}

async function main() {
  const shouldRestore = process.argv.includes("--restore");
  if (shouldRestore) {
    console.log("Restoring from backup before seeding...");
    await restoreFromBackup();
  }
  await ensureSuperAdmin();
  await ensureMockUsers();
  await seedChecklists();
  console.log("🌱 Database seeding completed!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
