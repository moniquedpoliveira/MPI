import * as React from 'react';
import {
  Html,
  Head,
  Body,
  Container,
  Section,
  Text,
  Heading,
  Hr,
  Link,
  Tailwind,
  Preview,
  Row,
  Column
} from '@react-email/components';

const ContractUpdateNotification = (props: any) => {
  const {
    contractNumber,
    contractTitle,
    supplier,
    manager,
    inspector,
    updateType,
    updateDescription,
    effectiveDate,
    contractValue,
    status,
    actionRequired,
    dueDate,
    systemLink
  } = props;

  return (
    <Html lang="pt-BR" dir="ltr">
      <Tailwind>
        <Head />
        <Preview>Atualização no Contrato {contractNumber} - {updateType}</Preview>
        <Body className="bg-gray-100 font-sans py-[40px]">
          <Container className="bg-white mx-auto px-[32px] py-[32px] rounded-[8px] max-w-[600px]">
            
            {/* Header */}
            <Section className="mb-[32px]">
              <Heading className="text-[24px] font-bold text-gray-900 mb-[8px] m-0">
                Notificação de Atualização Contratual
              </Heading>
              <Text className="text-[14px] text-gray-600 m-0">
                Sistema de Gestão de Contratos
              </Text>
            </Section>

            {/* Alert Box */}
            <Section className="bg-blue-50 border-l-[4px] border-blue-500 px-[16px] py-[16px] mb-[24px] rounded-r-[4px]">
              <Text className="text-[14px] font-semibold text-blue-800 m-0 mb-[4px]">
                🔔 {updateType}
              </Text>
              <Text className="text-[14px] text-blue-700 m-0">
                {updateDescription}
              </Text>
            </Section>

            {/* Contract Information */}
            <Section className="mb-[24px]">
              <Heading className="text-[18px] font-bold text-gray-900 mb-[16px] m-0">
                Informações do Contrato
              </Heading>
              
              <Row className="mb-[12px]">
                <Column>
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Número do Contrato:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0 font-bold">
                    {contractNumber}
                  </Text>
                </Column>
              </Row>

              <Row className="mb-[12px]">
                <Column>
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Objeto:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0">
                    {contractTitle}
                  </Text>
                </Column>
              </Row>

              <Row className="mb-[12px]">
                <Column>
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Fornecedor:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0">
                    {supplier}
                  </Text>
                </Column>
              </Row>

              <Row className="mb-[12px]">
                <Column className="w-1/2">
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Gestor:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0">
                    {manager}
                  </Text>
                </Column>
                <Column className="w-1/2">
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Fiscal:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0">
                    {inspector}
                  </Text>
                </Column>
              </Row>

              <Row className="mb-[12px]">
                <Column className="w-1/2">
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Valor do Contrato:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0 font-bold">
                    {contractValue}
                  </Text>
                </Column>
                <Column className="w-1/2">
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Status Atual:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0 font-bold">
                    {status}
                  </Text>
                </Column>
              </Row>

              <Row>
                <Column>
                  <Text className="text-[14px] text-gray-600 m-0 font-semibold">
                    Data de Vigência da Alteração:
                  </Text>
                  <Text className="text-[14px] text-gray-900 m-0">
                    {effectiveDate}
                  </Text>
                </Column>
              </Row>
            </Section>

            <Hr className="border-gray-200 my-[24px]" />

            {/* Action Required */}
            {actionRequired && (
              <Section className="bg-yellow-50 border-l-[4px] border-yellow-500 px-[16px] py-[16px] mb-[24px] rounded-r-[4px]">
                <Text className="text-[14px] font-semibold text-yellow-800 m-0 mb-[8px]">
                  ⚠️ Ação Necessária
                </Text>
                <Text className="text-[14px] text-yellow-700 m-0 mb-[8px]">
                  {actionRequired}
                </Text>
                {dueDate && (
                  <Text className="text-[14px] text-yellow-700 m-0 font-semibold">
                    Prazo: {dueDate}
                  </Text>
                )}
              </Section>
            )}

            {/* CTA Button */}
            <Section className="text-center mb-[32px]">
              <Link
                href={systemLink}
                className="bg-blue-600 text-white px-[24px] py-[12px] rounded-[6px] text-[14px] font-semibold no-underline box-border inline-block"
              >
                Acessar Sistema de Contratos
              </Link>
            </Section>

            <Hr className="border-gray-200 my-[24px]" />

            {/* Important Notes */}
            <Section className="mb-[24px]">
              <Text className="text-[14px] text-gray-700 m-0 mb-[12px]">
                <strong>Observações Importantes:</strong>
              </Text>
              <Text className="text-[14px] text-gray-700 m-0 mb-[8px]">
                • Mantenha-se atualizado sobre as modificações contratuais
              </Text>
              <Text className="text-[14px] text-gray-700 m-0 mb-[8px]">
                • Verifique se há documentos adicionais que necessitam assinatura
              </Text>
              <Text className="text-[14px] text-gray-700 m-0 mb-[8px]">
                • Em caso de dúvidas, entre em contato com a área responsável
              </Text>
              <Text className="text-[14px] text-gray-700 m-0">
                • Este é um email automático - não responda a esta mensagem
              </Text>
            </Section>

            {/* Footer */}
            <Section className="border-t border-gray-200 pt-[24px]">
              <Text className="text-[12px] text-gray-500 m-0 mb-[8px]">
                Sistema de Gestão de Contratos
              </Text>
              <Text className="text-[12px] text-gray-500 m-0 mb-[8px]">
                Departamento de Compras e Contratos
              </Text>
              <Text className="text-[12px] text-gray-500 m-0">
                © 2024 - Todos os direitos reservados
              </Text>
            </Section>

          </Container>
        </Body>
      </Tailwind>
    </Html>
  );
};

ContractUpdateNotification.PreviewProps = {
  contractNumber: "CT-2024-001234",
  contractTitle: "Prestação de Serviços de Manutenção Predial",
  supplier: "Empresa ABC Ltda - CNPJ: 12.345.678/0001-90",
  manager: "João Silva",
  inspector: "Maria Santos",
  updateType: "Alteração de Valor Contratual",
  updateDescription: "Aprovado aditivo para aumento do valor contratual em 15% devido à expansão do escopo dos serviços.",
  effectiveDate: "15 de Janeiro de 2025",
  contractValue: "R$ 575.000,00",
  status: "Vigente - Aditivo Aprovado",
  actionRequired: "Necessária assinatura digital do termo aditivo no sistema até a data limite.",
  dueDate: "20 de Janeiro de 2025",
  systemLink: "https://contratos.empresa.com.br/contrato/CT-2024-001234"
};

export default ContractUpdateNotification;