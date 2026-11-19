// A stand-in for the EMAIL send_email binding: keeps every message sent, or
// refuses as Email Sending does when `failWith` is set.
export type FakeEmail = SendEmail & { sent: EmailMessageBuilder[]; failWith: string | null }

export function fakeEmail(): FakeEmail {
  const sent: EmailMessageBuilder[] = []
  const binding = {
    sent,
    failWith: null as string | null,
    async send(message: EmailMessage | EmailMessageBuilder): Promise<EmailSendResult> {
      if (binding.failWith !== null) throw Object.assign(new Error(`${binding.failWith}: refused for ${"to" in message ? String(message.to) : "?"}`), { code: binding.failWith })
      sent.push(message as EmailMessageBuilder)
      return { messageId: `msg-${sent.length}` }
    },
  }
  return binding as FakeEmail
}

// The six digits a sent message carries.
export function sentCode(message: EmailMessageBuilder | undefined): string {
  const code = /Your Mehen code: (\d{6})$/.exec(message?.subject ?? "")?.[1]
  if (!code) throw new Error("No code in the message")
  return code
}
