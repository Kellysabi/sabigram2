// src/pages/api/clerk-webhook.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { buffer } from 'micro';
import axios from 'axios';
import prisma from '@/lib/prisma';

export const config = {
  api: {
    bodyParser: false,
  },
};

const webhookSecret = process.env.CLERK_WEBHOOK_SECRET as string;
const clerkApiKey = process.env.CLERK_API_KEY as string;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  const buf = await buffer(req);
  const rawBody = buf.toString('utf8');

  let event;

  try {
    // Verify the webhook signature
    const signature = req.headers['clerk-signature'] as string;
    event = verifyClerkWebhook(rawBody, signature, webhookSecret);
  } catch (err) {
    console.error('Webhook verification failed:', err);
    return res.status(400).send('Webhook verification failed');
  }

  const { type, data } = event;

  if (type === 'user.updated') {
    const { id } = data;

    try {
      // Fetch user data from Clerk
      const response = await axios.get(`https://api.clerk.dev/v1/users/${id}`, {
        headers: {
          Authorization: `Bearer ${clerkApiKey}`,
        },
      });

      const { username, profile_image_url } = response.data;

      // Update user data in the database
      await prisma.user.update({
        where: { clerkId: id },
        data: {
          username,
          image: profile_image_url,
        },
      });
    } catch (error) {
      console.error('Error updating user profile:', error);
      return res.status(500).send('Error updating user profile');
    }
  }

  res.status(200).send('Webhook received');
}

// Function to verify Clerk webhook signature
function verifyClerkWebhook(payload: string, signature: string, secret: string) {
  const crypto = require('crypto');
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('hex');

  if (expectedSignature !== signature) {
    throw new Error('Invalid webhook signature');
  }

  return JSON.parse(payload);
}
