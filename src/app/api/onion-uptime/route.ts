import { checkOnionUptime } from '@/services/torService';

export async function POST(req: Request) {
  try {
    const { onion } = await req.json();

    if (!onion) {
      return Response.json({ error: 'Missing onion URL' }, { status: 400 });
    }

    const result = await checkOnionUptime(onion);

    return Response.json(result);
  } catch (err) {
    console.error('Uptime error:', err);
    return Response.json(
      { error: 'Uptime check failed' },
      { status: 500 }
    );
  }
}
