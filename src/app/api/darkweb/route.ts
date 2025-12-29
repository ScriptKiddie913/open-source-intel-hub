import {
  discoverOnionSites,
  searchDarkWebSignals,
} from '@/services/torService';

export async function POST(req: Request) {
  try {
    const { query } = await req.json();

    if (!query || typeof query !== 'string') {
      return Response.json({ error: 'Invalid query' }, { status: 400 });
    }

    const [onions, signals] = await Promise.all([
      discoverOnionSites(query),
      searchDarkWebSignals(query),
    ]);

    return Response.json({
      onions,
      signals,
      meta: {
        queriedAt: new Date().toISOString(),
        query,
      },
    });
  } catch (err) {
    console.error('Darkweb API error:', err);
    return Response.json(
      { error: 'Dark web scan failed' },
      { status: 500 }
    );
  }
}
