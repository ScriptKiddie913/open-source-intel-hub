import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const response = await fetch(
      'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
      { cache: 'no-store' }
    );

    if (!response.ok) {
      return NextResponse.json(
        { error: 'Failed to fetch IPsum feed' },
        { status: 500 }
      );
    }

    const text = await response.text();

    return NextResponse.json({
      source: 'IPsum',
      fetchedAt: new Date().toISOString(),
      data: text
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Backend fetch failed' },
      { status: 500 }
    );
  }
}
