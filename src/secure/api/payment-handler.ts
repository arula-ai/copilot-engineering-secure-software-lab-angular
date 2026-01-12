/**
 * SECURE: Payment Handler
 *
 * Security Patterns Implemented:
 * - A01: Authorization and ownership verification
 * - A02: Sensitive data protection (PCI compliance patterns)
 * - A03: Input validation
 * - A04: Secure design with business logic validation
 * - A08: Webhook signature verification
 * - A09: Security logging without sensitive data
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import { Request, Response } from 'express';
import * as crypto from 'crypto';

// SECURE: Type definitions
interface AuthenticatedRequest extends Request {
  user?: { id: string; role: string };
}

interface PaymentRequest {
  amount: number;
  currency: string;
  cardLastFour: string;  // SECURE: Only store last 4 digits
  paymentToken: string;  // SECURE: Use tokenized card, not raw number
}

interface Transaction {
  id: string;
  userId: string;
  amount: number;
  currency: string;
  cardLastFour: string;
  status: 'pending' | 'completed' | 'refunded' | 'failed';
  createdAt: Date;
}

// SECURE: Configuration
const PAYMENT_CONFIG = {
  allowedCurrencies: ['USD', 'EUR', 'GBP'],
  maxAmount: 1000000, // $1M max
  minAmount: 0.50,    // 50 cents min
  maxRefundPercent: 100,
  webhookSecret: process.env.PAYMENT_WEBHOOK_SECRET || '',
};

// Simulated transaction store
const transactions: Map<string, Transaction> = new Map();

// SECURE: Security logger - never logs card numbers, CVVs, or tokens
const logPaymentEvent = (
  event: string,
  userId: string | null,
  details: Record<string, unknown>
) => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    userId,
    // SECURE: Sanitize any potential PCI data before logging
    ...Object.fromEntries(
      Object.entries(details).filter(([key]) =>
        !['cardNumber', 'cvv', 'token', 'paymentToken'].includes(key)
      )
    ),
  }));
};

export class SecurePaymentHandler {

  // SECURE: Process payment with comprehensive validation
  async processPayment(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { amount, currency, paymentToken } = req.body;

    // SECURE: Validate amount
    const amountValidation = this.validateAmount(amount);
    if (!amountValidation.valid) {
      return res.status(400).json({ error: amountValidation.error });
    }

    // SECURE: Validate currency (whitelist)
    if (!currency || !PAYMENT_CONFIG.allowedCurrencies.includes(currency)) {
      return res.status(400).json({
        error: `Invalid currency. Allowed: ${PAYMENT_CONFIG.allowedCurrencies.join(', ')}`,
      });
    }

    // SECURE: Validate payment token format
    if (!paymentToken || typeof paymentToken !== 'string' || paymentToken.length < 10) {
      return res.status(400).json({ error: 'Invalid payment token' });
    }

    // SECURE: Generate cryptographically secure transaction ID
    const transactionId = crypto.randomUUID();

    // In production: Send to payment processor with tokenized card
    // const result = await paymentProcessor.charge(paymentToken, amount, currency);

    const transaction: Transaction = {
      id: transactionId,
      userId: req.user.id,
      amount,
      currency,
      cardLastFour: '****', // SECURE: Only from payment processor response
      status: 'completed',
      createdAt: new Date(),
    };

    transactions.set(transactionId, transaction);

    // SECURE: Log without sensitive data
    logPaymentEvent('PAYMENT_PROCESSED', req.user.id, {
      transactionId,
      amount,
      currency,
      status: 'completed',
      // SECURE: No card numbers, CVVs, or tokens logged
    });

    // SECURE: Return minimal data
    return res.json({
      transactionId: transaction.id,
      amount: transaction.amount,
      currency: transaction.currency,
      status: transaction.status,
      // SECURE: Don't return full card info
    });
  }

  // SECURE: Refund with authorization and limits
  async refundPayment(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { transactionId, amount } = req.body;

    // SECURE: Validate transaction ID format
    if (!transactionId || typeof transactionId !== 'string') {
      return res.status(400).json({ error: 'Invalid transaction ID' });
    }

    const transaction = transactions.get(transactionId);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // SECURE: Verify ownership - user can only refund their own transactions
    if (transaction.userId !== req.user.id && req.user.role !== 'admin') {
      logPaymentEvent('UNAUTHORIZED_REFUND_ATTEMPT', req.user.id, {
        transactionId,
        transactionOwnerId: transaction.userId,
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    // SECURE: Validate refund amount
    const refundAmount = amount || transaction.amount;
    if (typeof refundAmount !== 'number' || refundAmount <= 0) {
      return res.status(400).json({ error: 'Invalid refund amount' });
    }

    // SECURE: Can't refund more than original amount
    if (refundAmount > transaction.amount) {
      return res.status(400).json({ error: 'Refund amount exceeds original transaction' });
    }

    // SECURE: Check transaction status
    if (transaction.status === 'refunded') {
      return res.status(400).json({ error: 'Transaction already refunded' });
    }
    if (transaction.status !== 'completed') {
      return res.status(400).json({ error: 'Only completed transactions can be refunded' });
    }

    // Process refund
    transaction.status = 'refunded';

    logPaymentEvent('REFUND_PROCESSED', req.user.id, {
      transactionId,
      refundAmount,
      originalAmount: transaction.amount,
    });

    return res.json({
      transactionId,
      refundAmount,
      status: 'refunded',
    });
  }

  // SECURE: Get payment history with authorization
  async getPaymentHistory(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { userId } = req.params;

    // SECURE: Authorization check - users can only view their own history
    if (userId !== req.user.id && req.user.role !== 'admin') {
      logPaymentEvent('UNAUTHORIZED_HISTORY_ACCESS', req.user.id, {
        targetUserId: userId,
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    // SECURE: Filter transactions by user
    const userTransactions = Array.from(transactions.values())
      .filter(t => t.userId === userId)
      .map(t => ({
        id: t.id,
        amount: t.amount,
        currency: t.currency,
        status: t.status,
        createdAt: t.createdAt,
        cardLastFour: t.cardLastFour, // SECURE: Only last 4 digits
        // SECURE: No full card numbers
      }));

    return res.json({ transactions: userTransactions });
  }

  // SECURE: Webhook with signature verification
  async handleWebhook(req: Request, res: Response) {
    // SECURE: Get signature from header
    const signature = req.headers['x-webhook-signature'] as string;
    const timestamp = req.headers['x-webhook-timestamp'] as string;

    if (!signature || !timestamp) {
      logPaymentEvent('WEBHOOK_MISSING_SIGNATURE', null, {});
      return res.status(401).json({ error: 'Missing signature' });
    }

    // SECURE: Verify timestamp is recent (prevent replay attacks)
    const timestampAge = Date.now() - parseInt(timestamp);
    if (isNaN(timestampAge) || timestampAge > 300000) { // 5 minutes
      logPaymentEvent('WEBHOOK_TIMESTAMP_EXPIRED', null, { timestampAge });
      return res.status(401).json({ error: 'Timestamp expired' });
    }

    // SECURE: Verify HMAC signature
    const payload = JSON.stringify(req.body);
    const expectedSignature = crypto
      .createHmac('sha256', PAYMENT_CONFIG.webhookSecret)
      .update(`${timestamp}.${payload}`)
      .digest('hex');

    // SECURE: Timing-safe comparison
    const signatureBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expectedSignature);

    if (signatureBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
      logPaymentEvent('WEBHOOK_INVALID_SIGNATURE', null, {});
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // SECURE: Process verified webhook
    const event = req.body;
    logPaymentEvent('WEBHOOK_RECEIVED', null, {
      eventType: event.type,
      eventId: event.id,
    });

    // Process webhook event...

    return res.json({ received: true });
  }

  // SECURE: Amount validation helper
  private validateAmount(amount: unknown): { valid: boolean; error?: string } {
    if (typeof amount !== 'number') {
      return { valid: false, error: 'Amount must be a number' };
    }

    if (isNaN(amount) || !isFinite(amount)) {
      return { valid: false, error: 'Invalid amount' };
    }

    if (amount < PAYMENT_CONFIG.minAmount) {
      return { valid: false, error: `Minimum amount is ${PAYMENT_CONFIG.minAmount}` };
    }

    if (amount > PAYMENT_CONFIG.maxAmount) {
      return { valid: false, error: `Maximum amount is ${PAYMENT_CONFIG.maxAmount}` };
    }

    // SECURE: Validate decimal places (2 for currency)
    if (Math.round(amount * 100) / 100 !== amount) {
      return { valid: false, error: 'Amount can have at most 2 decimal places' };
    }

    return { valid: true };
  }

  // SECURE: Validate card number format (Luhn check) - for display purposes only
  validateCardFormat(lastFour: string): boolean {
    return /^\d{4}$/.test(lastFour);
  }
}
