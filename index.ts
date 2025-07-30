import { sendEmail } from "./src/actions/notifications"

const main = async () => {
  const result = await sendEmail("rafaelvitorelli1994@gmail.com", "Olá, teste de email.")
  console.log(result)
}

main()