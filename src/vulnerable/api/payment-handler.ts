/**
 * VULNERABLE: Payment Handler
 *
 * Security Issues:
 * - A01: Broken Access Control
 * - A02: Cryptographic Failures
 * - A04: Insecure Design
 * - A08: Data Integrity Failures
 */

import { Request, Response } from 'express';

interface PaymentRequest {
  amount: number;
  currency: string;
  cardNumber: string;
  cvv: string;
  userId: string;
}

export class PaymentHandler {

  // VULN: No input validation, logs sensitive data
  async processPayment(req: Request, res: Response) {
    const payment: PaymentRequest = req.body;

    // VULN: Logs credit card details
    console.log('Processing payment:', JSON.stringify(payment));

    // VULN: No amount validation - can be negative
    // VULN: No currency validation
    // VULN: No card validation

    const transaction = {
      id: Math.random().toString(),
      ...payment, // VULN: Stores full card number
      status: 'completed'
    };

    // VULN: Returns sensitive data
    return res.json(transaction);
  }

  // VULN: No authorization - any user can refund
  async refundPayment(req: Request, res: Response) {
    const { transactionId, amount } = req.body;

    // VULN: No ownership check
    // VULN: No refund limit validation
    // VULN: Can refund more than original amount

    return res.json({
      refunded: true,
      transactionId,
      amount
    });
  }

  // VULN: Insecure direct object reference
  async getPaymentHistory(req: Request, res: Response) {
    const { userId } = req.params;
    // Any user can view any other user's payment history
    return res.json([
      { id: '1', amount: 100, cardNumber: '4111111111111111' }
    ]);
  }

  // VULN: Webhook without signature verification
  async handleWebhook(req: Request, res: Response) {
    const event = req.body;
    // VULN: No signature verification
    // VULN: Trusts any incoming webhook
    console.log('Processing webhook:', event.type);
    return res.json({ received: true });
  }
}
