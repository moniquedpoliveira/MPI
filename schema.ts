import { z } from "zod"

// Helper for date validation in AAAA-MM-DD format
const dateSchema = z.string().refine(
  (val: string) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(val)) return false
    const date = new Date(val)
    const [year, month, day] = val.split("-").map(Number)
    return (
      date.getFullYear() === year && date.getMonth() + 1 === month && date.getDate() === day && !isNaN(date.getTime())
    )
  },
  { message: "Data inválida ou formato incorreto (esperado AAAA-MM-DD)" },
)

export const ContratoSchema = z.object({
  id: z.string(),
  numeroContrato: z.string().min(1, "Número do contrato é obrigatório."),
  processoAdministrativo: z.string().min(1, "Processo administrativo é obrigatório."),
  modalidadeLicitacao: z.string().min(1, "Modalidade é obrigatória."),
  objeto: z.string().min(1, "Objeto é obrigatório."),
  orgaoContratante: z.string().min(1, "Órgão contratante é obrigatório."),
  nomeContratada: z.string().min(1, "Nome da contratada é obrigatório."),
  cnpjContratada: z
    .string()
    .min(1, "CNPJ é obrigatório.")
    .regex(/^\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}$/, "CNPJ inválido. Formato esperado: XX.XXX.XXX/XXXX-XX"),
  representanteLegal: z.string().min(1, "Representante legal é obrigatório."),
  enderecoContratada: z.string().min(1, "Endereço é obrigatório."),
  telefoneContratada: z.string().min(1, "Telefone da contratada é obrigatório."),
  emailContratada: z.string().min(1, "E-mail da contratada é obrigatório.").email("E-mail da contratada inválido."),
  valorTotal: z.number().positive("Valor total deve ser um número positivo."),
  dataAssinatura: dateSchema,
  vigenciaInicio: dateSchema,
  vigenciaTermino: z.date().refine((val) => val > new Date(val), { message: "Data de término da vigência deve ser posterior à data de início." }),
  dataBaseReajuste: dateSchema.optional().or(z.literal("").transform(() => undefined)), // Allow empty string, transform to undefined
  indiceReajuste: z.string().optional(),
  tipoGarantia: z.string().optional(),
  valorGarantia: z.number().nonnegative("Valor da garantia não pode ser negativo.").optional(),
  vigenciaGarantia: dateSchema.optional().or(z.literal("").transform(() => undefined)),
  gestorContrato: z.string().min(1, "Gestor do contrato é obrigatório."),
  portariaGestor: z.string().optional(),
  emailGestor: z
    .string()
    .email("E-mail do gestor inválido.")
    .optional()
    .or(z.literal("").transform(() => undefined)),
  telefoneGestor: z.string().optional(),
  fiscalAdministrativo: z.string().optional(),
  portariaFiscalAdm: z.string().optional(),
  emailFiscalAdm: z
    .string()
    .email("E-mail do fiscal adm. inválido.")
    .optional()
    .or(z.literal("").transform(() => undefined)),
  telefoneFiscalAdm: z.string().optional(),
  fiscalTecnico: z.string().optional(),
  portariaFiscalTec: z.string().optional(),
  emailFiscalTec: z
    .string()
    .email("E-mail do fiscal téc. inválido.")
    .optional()
    .or(z.literal("").transform(() => undefined)),
  telefoneFiscalTec: z.string().optional(),
  fiscalSubstituto: z.string().optional(),
  portariaFiscalSub: z.string().optional(),
  emailFiscalSub: z
    .string()
    .email("E-mail do fiscal sub. inválido.")
    .optional()
    .or(z.literal("").transform(() => undefined)),
  sancaoAdministrativa: z.string().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
})
// Add superRefine for cross-field validation if needed, e.g., vigenciaTermino > vigenciaInicio
// .superRefine((data, ctx) => {
//   if (data.vigenciaInicio && data.vigenciaTermino && new Date(data.vigenciaTermino) <= new Date(data.vigenciaInicio)) {
//     ctx.addIssue({
//       code: z.ZodIssueCode.custom,
//       message: "A data de término da vigência deve ser posterior à data de início.",
//       path: ["vigenciaTermino"],
//     });
//   }
// });

export const PartialContratoSchema = ContratoSchema.partial().strip()