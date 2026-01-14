-- Create threat_intelligence table for storing threat data
CREATE TABLE IF NOT EXISTS public.threat_intelligence (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  source_id TEXT NOT NULL,
  source_name TEXT NOT NULL,
  threat_type TEXT NOT NULL DEFAULT 'malware',
  severity_level TEXT NOT NULL DEFAULT 'medium',
  confidence_level INTEGER NOT NULL DEFAULT 50,
  title TEXT NOT NULL DEFAULT 'Unknown Threat',
  description TEXT DEFAULT '',
  indicators JSONB DEFAULT '[]'::jsonb,
  ttps JSONB DEFAULT '[]'::jsonb,
  targets JSONB DEFAULT '[]'::jsonb,
  attribution JSONB,
  timeline JSONB,
  metadata JSONB DEFAULT '{}'::jsonb,
  tags TEXT[] DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  raw_data JSONB,
  user_id UUID
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_source ON public.threat_intelligence(source_name);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_type ON public.threat_intelligence(threat_type);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_severity ON public.threat_intelligence(severity_level);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_created ON public.threat_intelligence(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_source_id ON public.threat_intelligence(source_id, source_name);

-- Enable Row Level Security
ALTER TABLE public.threat_intelligence ENABLE ROW LEVEL SECURITY;

-- Create policies for public read access (threat intelligence should be publicly viewable)
CREATE POLICY "Threat intelligence is publicly readable"
ON public.threat_intelligence
FOR SELECT
USING (true);

-- Create policy for authenticated users to insert
CREATE POLICY "Authenticated users can insert threat intelligence"
ON public.threat_intelligence
FOR INSERT
TO authenticated
WITH CHECK (true);

-- Create policy for authenticated users to update
CREATE POLICY "Authenticated users can update threat intelligence"
ON public.threat_intelligence
FOR UPDATE
TO authenticated
USING (true);

-- Create policy for authenticated users to delete
CREATE POLICY "Authenticated users can delete threat intelligence"
ON public.threat_intelligence
FOR DELETE
TO authenticated
USING (true);

-- Enable realtime for this table
ALTER PUBLICATION supabase_realtime ADD TABLE public.threat_intelligence;

-- Create function to auto-delete old records when capacity exceeds 75%
CREATE OR REPLACE FUNCTION public.auto_cleanup_threat_intelligence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  record_count INTEGER;
  max_records INTEGER := 10000; -- Maximum allowed records
  threshold_count INTEGER;
  delete_count INTEGER;
BEGIN
  -- Get current record count
  SELECT COUNT(*) INTO record_count FROM public.threat_intelligence;
  
  -- Calculate 75% threshold
  threshold_count := (max_records * 75) / 100;
  
  -- If we're over 75%, delete oldest 25% of records
  IF record_count > threshold_count THEN
    delete_count := record_count - threshold_count + (max_records / 10); -- Delete 35% to create buffer
    
    DELETE FROM public.threat_intelligence
    WHERE id IN (
      SELECT id FROM public.threat_intelligence
      ORDER BY created_at ASC
      LIMIT delete_count
    );
    
    RAISE NOTICE 'Auto-cleanup: Deleted % oldest threat intelligence records', delete_count;
  END IF;
  
  RETURN NEW;
END;
$$;

-- Create trigger to run cleanup after each insert
CREATE TRIGGER trigger_auto_cleanup_threats
AFTER INSERT ON public.threat_intelligence
FOR EACH STATEMENT
EXECUTE FUNCTION public.auto_cleanup_threat_intelligence();